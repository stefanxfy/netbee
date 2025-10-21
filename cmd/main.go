package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"netbee/pkg/comm/color"
	"netbee/pkg/core"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type so_event -type firewall_event SocketFilter ../ebpf/netbee.ebpf.c -- -I/usr/include/x86_64-linux-gnu

// Global symbol resolver
var symbolResolver *core.SymbolResolver

func main() {
	// 自定义帮助信息，覆盖默认的 -h 行为
	flag.Usage = func() {
		core.ShowSimpleHelp()
	}

	// 命令行参数定义
	var (
		// 协议过滤参数
		protocols = flag.String("proto", "", "过滤协议，逗号分隔 (tcp,udp,icmp)")

		// 主机过滤参数
		srcHost = flag.String("shost", "", "过滤来源主机IP地址 (例如: 192.168.1.1)")
		dstHost = flag.String("dhost", "", "过滤目标主机IP地址 (例如: 8.8.8.8)")
		host    = flag.String("host", "", "过滤主机IP地址 (来源或目标IP匹配即可)")

		// 端口过滤参数
		srcPort = flag.Int("sport", 0, "过滤来源端口 (例如: 8080)")
		dstPort = flag.Int("dport", 0, "过滤目的端口 (例如: 80)")
		port    = flag.Int("port", 0, "过滤端口 (来源端口或目的端口匹配即可)")

		// 调试选项
		kfree = flag.Bool("kfree", false, "显示kfree_skb的调用栈信息")

		// 颜色输出选项
		noColor = flag.Bool("no-color", false, "禁用颜色输出")

		// 包数量控制选项
		packetCount = flag.Int("c", 0, "捕获指定数量的数据包后自动退出 (例如: -c 100)")

		// 其他选项
		help = flag.Bool("help", false, "显示更多帮助信息")
	)
	flag.Parse()

	if *help {
		core.ShowHelp()
		return
	}

	// 解析过滤条件
	filterConfig, err := core.ParseFilterConfig(*srcHost, *dstHost, *host, *protocols, *dstPort, *srcPort, *port)
	if err != nil {
		log.Fatalf("解析过滤条件失败: %v", err)
	}

	log.Printf("过滤条件: 来源主机=%s, 目标主机=%s, 主机=%s, 协议=%v, 目的端口=%d, 来源端口=%d, 端口=%d",
		filterConfig.SrcHostStr, filterConfig.DstHostStr, filterConfig.HostStr, filterConfig.Protocols, *dstPort, *srcPort, *port)

	// 输出系统信息用于调试
	log.Printf("系统架构: %s", runtime.GOARCH)
	log.Printf("操作系统: %s", runtime.GOOS)

	// kfree 初始化符号解析器
	if *kfree {
		var err error
		symbolResolver, err = core.NewSymbolResolver()
		if err != nil {
			log.Printf("Warning: Failed to initialize symbol resolver: %v", err)
			log.Printf("Stack traces will show raw addresses instead of function names")
		} else {
			log.Printf("Symbol resolver initialized successfully")
		}
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock:", err)
	}
	_ = os.RemoveAll("/sys/fs/bpf/sarmor")

	// 加载 eBPF 程序规范文件 (netbee.o)
	bpfPath := "./target/netbee.o"
	bpfSpec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			log.Printf("Verifier error: %+v\n", verifierError)
		}
		log.Printf("Failed to load eBPF spec: %v\n", err)
		os.Exit(1)
	}

	// 创建 eBPF 程序集合
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

	// 设置过滤配置到eBPF map
	if err := core.SetFilterConfig(coll, filterConfig, *kfree); err != nil {
		log.Printf("设置过滤配置失败: %v", err)
		os.Exit(1)
	}

	// 定义 kprobe 目标列表
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

	// 定义 kretprobe 目标列表
	kretprobeTargets := []struct {
		progName   string
		kernelFunc string
	}{
		{"handle_nf_hook_slow_ret", "nf_hook_slow"},
	}

	// 存储所有的 link 用于统一管理
	var kprobeLinks []link.Link
	var kretprobeLinks []link.Link

	// 附加 kprobe 程序
	for _, target := range kprobeTargets {
		prog := coll.Programs[target.progName]
		if prog == nil {
			log.Fatalf("Program '%s' not found in eBPF collection", target.progName)
		}

		link, err := link.Kprobe(target.kernelFunc, prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach kprobe to %s: %v", target.kernelFunc, err)
		}
		kprobeLinks = append(kprobeLinks, link)
	}

	// 附加 kretprobe 程序
	for _, target := range kretprobeTargets {
		prog := coll.Programs[target.progName]
		if prog == nil {
			log.Fatalf("Program '%s' not found in eBPF collection", target.progName)
		}

		link, err := link.Kretprobe(target.kernelFunc, prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach kretprobe to %s: %v", target.kernelFunc, err)
		}
		kretprobeLinks = append(kretprobeLinks, link)
	}

	// 统一关闭所有 link
	defer func() {
		for _, link := range kprobeLinks {
			link.Close()
		}
		for _, link := range kretprobeLinks {
			link.Close()
		}
	}()

	log.Println("成功附加 kprobe 到网络层和传输层函数")

	// Get the ring buffers
	rb, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Printf("Failed to create network packet ring buffer reader: %v\n", err)
		os.Exit(1)
	}
	defer rb.Close()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt, shutting down...")
		cancel()
	}()

	// 创建颜色管理器
	colorManager := color.NewColorManager(*noColor, false)

	// Start reading from network packet ring buffer
	go func() {
		log.Println("开始监控网络数据包...")
		if *packetCount > 0 {
			log.Printf("将捕获 %d 个数据包后自动退出", *packetCount)
		}
		// 输出字段名标题行
		fmt.Printf("%-20s %-15s %-15s %-8s %-6s %-17s %-3s %-20s\n",
			"Time", "SrcIP", "DstIP", "Protocol", "Length", "SrcMAC", "TTL", "Info")
		fmt.Printf("%-20s %-15s %-15s %-8s %-6s %-17s %-3s %-20s\n",
			"----", "-----", "-----", "--------", "------", "------", "---", "----")

		// 包计数器
		packetCounter := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rb.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Error reading from network packet ring buffer: %v", err)
					continue
				}

				// Parse the network packet event
				var event core.SoEvent
				if len(record.RawSample) < int(unsafe.Sizeof(event)) {
					log.Printf("Network packet event data too short: %d bytes", len(record.RawSample))
					continue
				}

				// Copy data directly from RawSample
				event = *(*core.SoEvent)(unsafe.Pointer(&record.RawSample[0]))

				// 增加包计数器
				packetCounter++

				// 使用颜色管理器格式化事件
				formattedEvent := colorManager.FormatEvent(&event, symbolResolver)

				// 输出格式化的事件
				formattedEvent.Print()

				// 检查是否达到指定的包数量
				if *packetCount > 0 && packetCounter >= *packetCount {
					log.Printf("已捕获 %d 个数据包，程序退出", packetCounter)
					cancel() // 触发程序退出
					return
				}
			}
		}
	}()
	// Wait for context cancellation
	<-ctx.Done()
	fmt.Println("监控已停止")
}
