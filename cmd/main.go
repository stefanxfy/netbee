package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"netbee/pkg/comm/color"
	"netbee/pkg/core"
	"netbee/pkg/diagnose"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type so_event -type firewall_event SocketFilter ../ebpf/netbee.ebpf.c -- -I/usr/include/x86_64-linux-gnu

// Global symbol resolver
var symbolResolver *core.SymbolResolver

type pendingEvent struct {
	group     *core.PacketEventGroup
	firstTime time.Time
}

type pendingGroupQueue struct {
	mu     sync.Mutex
	events []pendingEvent
}

func main() {
	flag.Usage = func() {
		core.ShowSimpleHelp()
	}

	var (
		protocols = flag.String("proto", "", "过滤协议，逗号分隔 (tcp,udp,icmp)")
		srcHost   = flag.String("shost", "", "过滤来源主机IP地址 (例如: 192.168.1.1)")
		dstHost   = flag.String("dhost", "", "过滤目标主机IP地址 (例如: 8.8.8.8)")
		host      = flag.String("host", "", "过滤主机IP地址 (来源或目标IP匹配即可)")

		srcPort = flag.Int("sport", 0, "过滤来源端口 (例如: 8080)")
		dstPort = flag.Int("dport", 0, "过滤目的端口 (例如: 80)")
		port    = flag.Int("port", 0, "过滤端口 (来源端口或目的端口匹配即可)")

		kfree        = flag.Bool("kfree", false, "显示kfree_skb的调用栈信息")
		noColor      = flag.Bool("no-color", false, "禁用颜色输出")
		packetCount  = flag.Int("c", 0, "捕获指定数量的数据包后自动退出 (例如: -c 100)")
		outputFile   = flag.String("w", "", "将输出内容保存到指定文件 (例如: -w output.txt)")
		showPacketID = flag.Bool("ID", false, "显示 packet ID，不进行合并（默认：合并相同 packet ID 的数据包）")

		enableAI  = flag.Bool("AI", false, "抓包结束前调用云端 AI 诊断，并将结果写入本地文件")
		aiUser    = flag.String("ai-user", defaultAIUser(), "AI 诊断请求中的 user 字段")
		aiOut     = flag.String("ai-out", "", "AI 诊断报告输出路径（默认按时间戳生成 .md 文件）")
		aiTimeout = flag.Duration("ai-timeout", 120*time.Second, "AI 诊断接口总超时时间")
		aiRawSave = flag.Bool("ai-raw-save", false, "保存 AI 原始响应 JSON 文件，便于调试")
		aiKeep    = flag.Bool("keep", false, "继续使用上次 AI 诊断的 conversation_id")
		aiAPIKey  = flag.String("ai-api-key", "", "AI 接口鉴权 token（默认读取 NETBEE_AI_API_KEY）")
		aiAPIURL  = flag.String("ai-api-url", "", "AI 接口地址（默认使用内置 Dify 地址）")

		help = flag.Bool("help", false, "显示更多帮助信息")
	)
	flag.Parse()

	if *help {
		core.ShowHelp()
		return
	}

	filterConfig, err := core.ParseFilterConfig(*srcHost, *dstHost, *host, *protocols, *dstPort, *srcPort, *port)
	if err != nil {
		log.Fatalf("解析过滤条件失败: %v", err)
	}

	log.Printf("过滤条件: 来源主机=%s, 目标主机=%s, 主机=%s, 协议=%v, 目的端口=%d, 来源端口=%d, 端口=%d",
		filterConfig.SrcHostStr, filterConfig.DstHostStr, filterConfig.HostStr, filterConfig.Protocols, *dstPort, *srcPort, *port)
	log.Printf("系统架构: %s", runtime.GOARCH)
	log.Printf("操作系统: %s", runtime.GOOS)

	aiOptions := diagnose.Options{
		Enabled:          *enableAI,
		APIURL:           *aiAPIURL,
		APIKey:           resolveAPIKey(*aiAPIKey),
		User:             *aiUser,
		OutputPath:       *aiOut,
		Timeout:          *aiTimeout,
		SaveRaw:          *aiRawSave,
		KeepConversation: *aiKeep,
		MemoryLimit:      2 * 1024 * 1024,
	}
	if aiOptions.Enabled && aiOptions.APIKey == "" {
		log.Fatal("启用 -AI 时必须通过 NETBEE_AI_API_KEY 或 -ai-api-key 提供接口鉴权 token")
	}

	if *kfree {
		symbolResolver, err = core.NewSymbolResolver()
		if err != nil {
			log.Printf("Warning: Failed to initialize symbol resolver: %v", err)
			log.Printf("Stack traces will show raw addresses instead of function names")
		} else {
			log.Printf("Symbol resolver initialized successfully")
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock:", err)
	}
	_ = os.RemoveAll("/sys/fs/bpf/sarmor")

	bpfSpec, err := ebpf.LoadCollectionSpec("./target/netbee.o")
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			log.Printf("Verifier error: %+v\n", verifierError)
		}
		log.Printf("Failed to load eBPF spec: %v\n", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(bpfSpec)
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			log.Printf("Verifier error: %+v\n", verifierError)
		}
		log.Printf("Failed to load eBPF collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	if err := core.SetFilterConfig(coll, filterConfig, *kfree); err != nil {
		log.Printf("设置过滤配置失败: %v", err)
		os.Exit(1)
	}

	kprobeTargets := []struct {
		progName   string
		kernelFunc string
	}{
		{"handle_netif_rx", "netif_rx"},
		{"handle_nf_hook_slow", "nf_hook_slow"},
		{"handle_ip_rcv", "ip_rcv"},
		{"handle_ip_local_deliver", "ip_local_deliver"},
		{"handle_dev_queue_xmit", "__dev_queue_xmit"},
		{"handle_tcp_v4_rcv", "tcp_v4_rcv"},
		{"handle_udp_rcv", "udp_rcv"},
		{"handle_icmp_rcv", "icmp_rcv"},
		{"handle_icmp_echo", "icmp_echo"},
		{"handle_icmp_unreach", "icmp_unreach"},
		{"handle_tcp_transmit_skb", "__tcp_transmit_skb"},
		{"handle_kfree_skb", "__kfree_skb"},
		{"handle_ip_queue_xmit", "__ip_queue_xmit"},
	}
	kretprobeTargets := []struct {
		progName   string
		kernelFunc string
	}{
		{"handle_nf_hook_slow_ret", "nf_hook_slow"},
	}

	var kprobeLinks []link.Link
	var kretprobeLinks []link.Link
	for _, target := range kprobeTargets {
		prog := coll.Programs[target.progName]
		if prog == nil {
			log.Fatalf("Program '%s' not found in eBPF collection", target.progName)
		}
		kprobeLink, err := link.Kprobe(target.kernelFunc, prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach kprobe to %s: %v", target.kernelFunc, err)
		}
		kprobeLinks = append(kprobeLinks, kprobeLink)
	}
	for _, target := range kretprobeTargets {
		prog := coll.Programs[target.progName]
		if prog == nil {
			log.Fatalf("Program '%s' not found in eBPF collection", target.progName)
		}
		kretprobeLink, err := link.Kretprobe(target.kernelFunc, prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach kretprobe to %s: %v", target.kernelFunc, err)
		}
		kretprobeLinks = append(kretprobeLinks, kretprobeLink)
	}
	defer func() {
		for _, item := range kprobeLinks {
			item.Close()
		}
		for _, item := range kretprobeLinks {
			item.Close()
		}
	}()
	log.Println("成功附加 kprobe 到网络层和传输层函数")

	rb, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Printf("Failed to create network packet ring buffer reader: %v\n", err)
		os.Exit(1)
	}
	defer rb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		stopOnce      sync.Once
		exitReason    = "正常退出"
		exitReasonMu  sync.Mutex
		packetCounter int64
		limitReached  atomic.Bool
	)
	packetLimit := int64(*packetCount)
	requestStop := func(reason string) {
		stopOnce.Do(func() {
			exitReasonMu.Lock()
			exitReason = reason
			exitReasonMu.Unlock()
			cancel()
			if err := rb.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("关闭 ring buffer 失败: %v", err)
			}
		})
	}
	getExitReason := func() string {
		exitReasonMu.Lock()
		defer exitReasonMu.Unlock()
		return exitReason
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt, shutting down...")
		requestStop("收到 Ctrl+C/SIGTERM，中断抓包")
	}()

	var outputWriter io.Writer = os.Stdout
	var outputFileHandle *os.File
	disableColor := *noColor
	if *outputFile != "" {
		disableColor = true
		outputFileHandle, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("无法创建输出文件 %s: %v", *outputFile, err)
		}
		outputWriter = outputFileHandle
		defer outputFileHandle.Close()
		log.Printf("输出将保存到文件: %s", *outputFile)
	}
	if aiOptions.Enabled && *outputFile == "" {
		outputWriter = io.Discard
		log.Println("AI 模式已启用，控制台不再输出抓包明细")
	}

	var captureBuffer *diagnose.CaptureBuffer
	if aiOptions.Enabled {
		captureBuffer = diagnose.NewCaptureBuffer(aiOptions.MemoryLimit)
		defer captureBuffer.Close()
		log.Printf("AI 诊断已启用，报告将写入: %s", defaultReportPathHint(aiOptions.OutputPath))
	}

	retransmissionDetector := core.NewRetransmissionDetector()
	eventColorManager := color.NewColorManager(disableColor, false)
	eventColorManager.SetRetransmissionDetector(retransmissionDetector)
	baseColorManager := color.NewColorManager(disableColor, false)

	var merger *core.PacketMerger
	if !*showPacketID {
		merger = core.NewPacketMerger(100 * time.Millisecond)
		log.Println("启用数据包合并功能（相同 packet ID 的数据包将合并显示）")
	} else {
		log.Println("启用 packet ID 显示功能（不进行合并，每个事件单独显示）")
	}

	startTime := time.Now()
	pendingQueue := &pendingGroupQueue{}
	recordPrinted := func() bool {
		current := atomic.AddInt64(&packetCounter, 1)
		if packetLimit > 0 && current >= packetLimit {
			limitReached.Store(true)
			log.Printf("已捕获 %d 个数据包，程序退出", current)
			requestStop(fmt.Sprintf("达到抓包数量上限(%d)", packetLimit))
			return false
		}
		return true
	}
	printDirectEvent := func(event *core.SoEvent) bool {
		formattedEvent := eventColorManager.FormatEvent(event, symbolResolver)
		if err := writeOutputLine(outputWriter, captureBuffer, formatTableLine(formattedEvent)); err != nil {
			log.Printf("写入输出失败: %v", err)
			requestStop("输出写入失败")
			return false
		}
		return recordPrinted()
	}
	printMergedGroup := func(group *core.PacketEventGroup) bool {
		mergedInfo, lastEvent := core.FormatMergedInfoWithRetransmission(group, symbolResolver, retransmissionDetector, !disableColor)
		if mergedInfo == "" || lastEvent == nil {
			return true
		}
		formattedEvent := baseColorManager.FormatEvent(lastEvent, symbolResolver)
		formattedEvent.Info = mergedInfo
		if err := writeOutputLine(outputWriter, captureBuffer, formatTableLine(formattedEvent)); err != nil {
			log.Printf("写入输出失败: %v", err)
			requestStop("输出写入失败")
			return false
		}
		return recordPrinted()
	}

	log.Println("开始监控网络数据包...")
	if *packetCount > 0 {
		log.Printf("将捕获 %d 个数据包后自动退出", *packetCount)
	}
	if err := writeOutputLine(outputWriter, captureBuffer, formatHeaderLine()); err != nil {
		log.Fatalf("写入标题失败: %v", err)
	}
	if err := writeOutputLine(outputWriter, captureBuffer, formatHeaderSeparatorLine()); err != nil {
		log.Fatalf("写入标题失败: %v", err)
	}

	var wg sync.WaitGroup
	if merger != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case key := <-merger.GetFlushChan():
					group := merger.GetAndRemoveGroup(key)
					if group != nil {
						pendingQueue.Enqueue(group)
					}
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					for _, group := range pendingQueue.Drain() {
						if !printMergedGroup(group) {
							return
						}
					}
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
					return
				}
				log.Printf("Error reading from network packet ring buffer: %v", err)
				continue
			}

			var event core.SoEvent
			if len(record.RawSample) < int(unsafe.Sizeof(event)) {
				log.Printf("Network packet event data too short: %d bytes", len(record.RawSample))
				continue
			}
			event = *(*core.SoEvent)(unsafe.Pointer(&record.RawSample[0]))

			if *showPacketID {
				if !printDirectEvent(&event) {
					return
				}
				continue
			}

			if !merger.AddEvent(&event) {
				continue
			}
			group := merger.GetAndRemoveGroup(core.GetPacketKey(&event))
			if group == nil {
				continue
			}
			if !printMergedGroup(group) {
				return
			}
		}
	}()

	<-ctx.Done()
	wg.Wait()

	if merger != nil && !limitReached.Load() {
		for _, group := range merger.DrainGroups() {
			pendingQueue.Enqueue(group)
		}
		for _, group := range pendingQueue.Drain() {
			if !printMergedGroup(group) {
				break
			}
		}
	}

	if outputFileHandle != nil {
		_ = outputFileHandle.Sync()
	}

	log.Printf("监控已停止，退出原因: %s", getExitReason())
	if aiOptions.Enabled {
		log.Println("开始执行 AI 诊断...")
		reportOutput, err := runAIDiagnosis(aiOptions, captureBuffer, startTime, getExitReason())
		if err != nil {
			log.Printf("AI 诊断失败: %v", err)
			if reportOutput != nil {
				if reportOutput.CaptureDownloadURL != "" {
					log.Printf("抓包文件下载链接: %s", reportOutput.CaptureDownloadURL)
				}
				if reportOutput.ConversationIDPath != "" {
					log.Printf("AI 会话 ID 已保存: %s", reportOutput.ConversationIDPath)
				}
				log.Printf("诊断报告已写入: %s", reportOutput.ReportPath)
				if reportOutput.RawResponsePath != "" {
					log.Printf("AI 原始响应已保存: %s", reportOutput.RawResponsePath)
				}
			}
		} else if reportOutput != nil {
			printDiagnosisPreview(reportOutput.ReportPath)
			if reportOutput.CaptureDownloadURL != "" {
				log.Printf("抓包文件下载链接: %s", reportOutput.CaptureDownloadURL)
			}
			if reportOutput.ConversationIDPath != "" {
				log.Printf("AI 会话 ID 已保存: %s", reportOutput.ConversationIDPath)
			}
			log.Printf("AI 诊断完成，详细报告见: %s", reportOutput.ReportPath)
			if reportOutput.RawResponsePath != "" {
				log.Printf("AI 原始响应已保存: %s", reportOutput.RawResponsePath)
			}
		}
	}

	fmt.Println("监控已停止")
}

func defaultAIUser() string {
	user := os.Getenv("USER")
	if user == "" {
		return "netbee"
	}
	return user
}

func resolveAPIKey(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue)
	}
	return strings.TrimSpace(os.Getenv("NETBEE_AI_API_KEY"))
}

func defaultReportPathHint(path string) string {
	if path != "" {
		return path
	}
	return "diagnosis-YYYYMMDD-HHMMSS.md"
}

func printDiagnosisPreview(reportPath string) {
	lines, err := extractDiagnosisPreview(reportPath, 5)
	if err != nil {
		log.Printf("读取 AI 诊断摘要失败: %v", err)
		return
	}
	if len(lines) == 0 {
		return
	}
	lines = formatDiagnosisPreviewLines(lines)
	if len(lines) == 0 {
		return
	}

	log.Println("AI 诊断摘要:")
	for _, line := range lines {
		log.Printf("  %s", line)
	}
}

func extractDiagnosisPreview(reportPath string, maxLines int) ([]string, error) {
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, err
	}

	text := string(content)
	lines := make([]string, 0, 12)
	lines = append(lines, extractPreferredSummaryLines(text)...)
	lines = append(lines, extractConclusionPreviewLines(text, maxLines)...)
	return lines, nil
}

func extractSection(content, startMarker, endMarker string) string {
	start := strings.Index(content, startMarker)
	if start == -1 {
		return ""
	}

	section := content[start+len(startMarker):]
	section = strings.TrimLeft(section, "\r\n")

	if endMarker != "" {
		if end := strings.Index(section, endMarker); end != -1 {
			section = section[:end]
		}
	}

	return strings.TrimSpace(section)
}

func extractPreferredSummaryLines(content string) []string {
	targetPrefixes := []string{
		"- 抓包文本大小:",
		"- 抓包有效行数:",
		"- 协议分布:",
		"- DROP 次数:",
		"- TCP 重传次数:",
		"- RST 次数:",
	}

	rawLines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	result := make([]string, 0, len(targetPrefixes))
	for _, prefix := range targetPrefixes {
		for _, line := range rawLines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, prefix) {
				result = append(result, line)
				break
			}
		}
	}

	return result
}

func extractConclusionPreviewLines(content string, maxLines int) []string {
	section := extractSection(content, "# 综合结论", "## AI 调用元数据")
	if section == "" {
		section = extractSection(content, "## 综合结论", "## AI 调用元数据")
	}
	if section == "" {
		section = extractSection(content, "# 结论", "## AI 调用元数据")
	}
	if section == "" {
		section = extractSection(content, "## 结论", "## AI 调用元数据")
	}
	if section == "" {
		return nil
	}

	rawLines := strings.Split(strings.ReplaceAll(section, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(rawLines)+1)
	lines = append(lines, "# 综合结论")
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "```") {
			continue
		}
		lines = append(lines, line)
		if line == "---" {
			break
		}
	}

	return lines
}

func formatDiagnosisPreviewLines(lines []string) []string {
	result := make([]string, 0, len(lines))
	headingIndex := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			title := strings.TrimSpace(strings.TrimLeft(line, "#"))
			if title == "" {
				continue
			}
			if title == "综合结论" {
				result = append(result, title)
				continue
			}

			headingIndex++
			result = append(result, fmt.Sprintf("%d. %s", headingIndex, title))
			continue
		}

		if line == "---" {
			result = append(result, line)
			continue
		}

		if stripped, ok := trimNumericListPrefix(line); ok {
			line = stripped
		}

		if strings.HasPrefix(line, "- ") {
			result = append(result, line)
			continue
		}

		result = append(result, "- "+line)
	}

	return result
}

func trimNumericListPrefix(line string) (string, bool) {
	if line == "" {
		return line, false
	}

	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || i+1 >= len(line) || line[i] != '.' || line[i+1] != ' ' {
		return line, false
	}

	return strings.TrimSpace(line[i+2:]), true
}

func formatHeaderLine() string {
	return fmt.Sprintf("%-20s %-15s %-15s %-8s %-6s %-17s %-3s %-20s\n",
		"Time", "SrcIP", "DstIP", "Protocol", "Length", "SrcMAC", "TTL", "Info")
}

func formatHeaderSeparatorLine() string {
	return fmt.Sprintf("%-20s %-15s %-15s %-8s %-6s %-17s %-3s %-20s\n",
		"----", "-----", "-----", "--------", "------", "------", "---", "----")
}

func formatTableLine(formattedEvent *color.FormattedEvent) string {
	return fmt.Sprintf("%-20s %-15s %-15s %-8s %-6d %-17s %-3s %-20s\n",
		formattedEvent.Time, formattedEvent.SrcIP, formattedEvent.DstIP,
		formattedEvent.Protocol, formattedEvent.Length, formattedEvent.SrcMAC,
		formattedEvent.TTL, formattedEvent.Info)
}

func writeOutputLine(outputWriter io.Writer, captureBuffer *diagnose.CaptureBuffer, line string) error {
	if _, err := io.WriteString(outputWriter, line); err != nil {
		return err
	}
	if captureBuffer != nil {
		return captureBuffer.WritePlainText(line)
	}
	return nil
}

func runAIDiagnosis(opts diagnose.Options, captureBuffer *diagnose.CaptureBuffer, startTime time.Time, exitReason string) (*diagnose.ReportOutput, error) {
	if captureBuffer == nil {
		return nil, fmt.Errorf("未找到 AI 诊断抓包内容")
	}
	reportPath := diagnose.ResolveReportPath(opts.OutputPath, time.Now())
	opts.OutputPath = reportPath
	if opts.KeepConversation {
		conversationID, conversationPath, err := diagnose.LoadConversationID(reportPath)
		if err != nil {
			return nil, err
		}
		if conversationID != "" {
			opts.ConversationID = conversationID
			log.Printf("检测到上次 AI 会话文件，准备校验合法性: %s", conversationPath)
		} else {
			log.Printf("未找到上次 conversation_id 文件，按首次诊断处理: %s", conversationPath)
		}
	}

	captureBytes, err := captureBuffer.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("读取抓包内容失败: %w", err)
	}

	summary := diagnose.BuildSummary(
		string(captureBytes),
		captureBuffer.Size(),
		strings.Join(os.Args, " "),
		startTime,
		time.Now(),
		exitReason,
	)

	client := diagnose.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	if strings.TrimSpace(opts.ConversationID) != "" {
		valid, err := client.ValidateConversation(ctx, opts.User, opts.ConversationID)
		if err != nil {
			log.Printf("校验 conversation_id 失败，将继续尝试沿用会话: %v", err)
		} else if !valid {
			log.Printf("conversation_id 预检无效，按首次诊断处理: %s", opts.ConversationID)
			opts.ConversationID = ""
		} else {
			log.Printf("conversation_id 校验通过，继续沿用历史会话")
		}
	}

	result, analyzeErr := client.Analyze(ctx, opts, summary, captureBytes)
	var rawResponse []byte
	if apiErr, ok := analyzeErr.(*diagnose.APIError); ok {
		rawResponse = []byte(apiErr.Body)
	}
	reportOutput, reportErr := diagnose.WriteReport(diagnose.ReportInput{
		Summary:       summary,
		Result:        result,
		ReportError:   analyzeErr,
		RawResponse:   rawResponse,
		RawSave:       opts.SaveRaw,
		RequestedPath: reportPath,
	})
	if reportErr != nil {
		return nil, reportErr
	}
	if analyzeErr != nil {
		return reportOutput, analyzeErr
	}
	return reportOutput, nil
}

func (q *pendingGroupQueue) Enqueue(group *core.PacketEventGroup) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, pendingEvent{
		group:     group,
		firstTime: group.GetFirstTime(),
	})
}

func (q *pendingGroupQueue) Drain() []*core.PacketEventGroup {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.events) == 0 {
		return nil
	}

	events := make([]pendingEvent, len(q.events))
	copy(events, q.events)
	q.events = q.events[:0]

	for i := 0; i < len(events)-1; i++ {
		for j := i + 1; j < len(events); j++ {
			if events[i].firstTime.After(events[j].firstTime) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}

	groups := make([]*core.PacketEventGroup, 0, len(events))
	for _, event := range events {
		groups = append(groups, event.group)
	}
	return groups
}
