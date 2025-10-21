package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"netbee/pkg/http"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type http_event HTTPMonitor ../ebpf/netbee-http.ebpf.c -- -I/usr/include/x86_64-linux-gnu

// findLibraryPath 查找SSL库的路径
func findLibraryPath(libname string) (string, error) {
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ldconfig: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, libname) {
			// 格式: libssl3.so (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl3.so
			parts := strings.Split(line, "=>")
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if _, err := os.Stat(path); err == nil {
					return path, nil
				}
			}
		}
	}

	return "", fmt.Errorf("library %s not found", libname)
}

// attachSSLUprobes 附加SSL uprobe程序
func attachSSLUprobes(coll *ebpf.Collection, libsslPath string) ([]link.Link, error) {
	var links []link.Link

	// 获取SSL uprobe程序
	sslReadEntry := coll.Programs["handle_ssl_read_entry"]
	sslReadExit := coll.Programs["handle_ssl_read_exit"]
	sslWriteEntry := coll.Programs["handle_ssl_write_entry"]
	sslWriteExit := coll.Programs["handle_ssl_write_exit"]

	if sslReadEntry == nil || sslReadExit == nil || sslWriteEntry == nil || sslWriteExit == nil {
		return nil, fmt.Errorf("SSL uprobe programs not found")
	}

	// 附加SSL_read uprobe
	sslReadLink, err := link.OpenExecutable(libsslPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable %s: %v", libsslPath, err)
	}

	// SSL_read entry
	readEntryLink, err := sslReadLink.Uprobe("SSL_read", sslReadEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach SSL_read entry uprobe: %v", err)
	}
	links = append(links, readEntryLink)

	// SSL_read exit
	readExitLink, err := sslReadLink.Uretprobe("SSL_read", sslReadExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach SSL_read exit uprobe: %v", err)
	}
	links = append(links, readExitLink)

	// SSL_write entry
	writeEntryLink, err := sslReadLink.Uprobe("SSL_write", sslWriteEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach SSL_write entry uprobe: %v", err)
	}
	links = append(links, writeEntryLink)

	// SSL_write exit
	writeExitLink, err := sslReadLink.Uretprobe("SSL_write", sslWriteExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach SSL_write exit uprobe: %v", err)
	}
	links = append(links, writeExitLink)

	return links, nil
}

func main() {
	// 自定义帮助信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "HTTP/HTTPS监控工具\n\n")
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  %s                    # 监控所有HTTP/HTTPS流量\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -method GET        # 监控GET请求\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -status 200        # 监控200状态码\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -body              # 显示响应体\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -host 192.168.1.1  # 监控特定主机\n", os.Args[0])
	}

	// 命令行参数定义
	var (
		parseBody      = flag.Bool("body", false, "解析HTTP/HTTPS响应体内容")
		httpMethod     = flag.String("method", "", "过滤HTTP请求方法 (例如: GET,POST)")
		httpStatus     = flag.Int("status", 0, "过滤HTTP状态码 (例如: 200,404)")
		httpUri        = flag.String("uri", "", "过滤HTTP URI模式 (例如: /api/*)")
		shost          = flag.String("shost", "", "过滤来源主机IP地址")
		dhost          = flag.String("dhost", "", "过滤目标主机IP地址")
		host           = flag.String("host", "", "过滤主机IP地址")
		sport          = flag.Int("sport", 0, "过滤来源端口")
		dport          = flag.Int("dport", 0, "过滤目标端口")
		port           = flag.Int("port", 0, "过滤端口")
		interfaceName  = flag.String("interface", "", "网络接口名称 (例如: eth0, wlan0)，为空则监控所有接口")
		listInterfaces = flag.Bool("list-interfaces", false, "列出所有可用的网络接口")
		help           = flag.Bool("help", false, "显示帮助信息")
	)
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	// 如果用户要求列出接口，则列出并退出
	if *listInterfaces {
		im := http.NewInterfaceManager()
		interfaces, err := im.GetNetworkInterfaces()
		if err != nil {
			log.Fatalf("获取网络接口失败: %v", err)
		}

		fmt.Println("可用的网络接口:")
		fmt.Printf("%-10s %-15s %-20s %s\n", "名称", "状态", "MAC地址", "IP地址")
		fmt.Println(strings.Repeat("-", 60))

		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			var ipAddr string
			if len(addrs) > 0 {
				ipAddr = addrs[0].String()
			}

			status := "UP"
			if iface.Flags&net.FlagUp == 0 {
				status = "DOWN"
			}

			fmt.Printf("%-10s %-15s %-20s %s\n",
				iface.Name, status, iface.HardwareAddr.String(), ipAddr)
		}
		return
	}

	// 解析过滤配置
	filterConfig, err := http.ParseHTTPFilterConfig(*shost, *dhost, *host,
		*dport, *sport, *port,
		*httpMethod, *httpStatus, *httpUri)
	if err != nil {
		log.Fatalf("解析过滤条件失败: %v", err)
	}

	log.Printf("过滤条件: 来源主机=%s, 目标主机=%s, 主机=%s, 目的端口=%d, 来源端口=%d, 端口=%d, HTTP方法=%s, HTTP状态码=%d, HTTP URI=%s",
		*shost, *dhost, *host, *dport, *sport, *port, *httpMethod, *httpStatus, *httpUri)

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock:", err)
	}

	// 清理旧的BPF文件
	_ = os.RemoveAll("/sys/fs/bpf/netbee-http")

	// 加载eBPF程序
	bpfPath := "./target/netbee-http.o"
	bpfSpec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(bpfSpec)
	if err != nil {
		log.Fatalf("Failed to load eBPF collection: %v", err)
	}
	defer coll.Close()

	// 设置过滤配置
	if err := http.SetHTTPFilterConfig(coll, filterConfig); err != nil {
		log.Fatalf("设置过滤配置失败: %v", err)
	}

	// 获取socket filter程序
	socketFilter := coll.Programs["handle_http_traffic"]
	if socketFilter == nil {
		log.Fatal("handle_http_traffic program not found")
	}

	// 获取SSL uprobe程序
	sslReadEntry := coll.Programs["handle_ssl_read_entry"]
	sslReadExit := coll.Programs["handle_ssl_read_exit"]
	sslWriteEntry := coll.Programs["handle_ssl_write_entry"]
	sslWriteExit := coll.Programs["handle_ssl_write_exit"]

	// 创建接口管理器
	im := http.NewInterfaceManager()
	defer im.Close()

	// 根据参数决定附加策略
	if *interfaceName != "" {
		// 附加到指定接口
		log.Printf("正在附加socket filter到接口: %s", *interfaceName)
		err = im.AttachToInterface(*interfaceName, socketFilter)
		if err != nil {
			log.Fatalf("附加到接口 %s 失败: %v", *interfaceName, err)
		}
		log.Printf("✓ 成功附加到接口: %s", *interfaceName)
	} else {
		// 附加到所有接口
		log.Println("正在附加socket filter到所有网络接口...")
		err = im.AttachToAllInterfaces(socketFilter)
		if err != nil {
			log.Fatalf("附加到网络接口失败: %v", err)
		}
		log.Println("✓ 成功附加到所有网络接口")
	}

	// 附加SSL uprobe程序（如果存在）
	var sslLinks []link.Link
	if sslReadEntry != nil && sslReadExit != nil && sslWriteEntry != nil && sslWriteExit != nil {
		log.Println("正在查找SSL库...")

		// 尝试查找不同的SSL库
		sslLibs := []string{"libssl.so", "libssl.so.3", "libssl.so.1.1", "libssl.so.1.0"}
		var libsslPath string
		var err error

		for _, lib := range sslLibs {
			libsslPath, err = findLibraryPath(lib)
			if err == nil {
				log.Printf("找到SSL库: %s", libsslPath)
				break
			}
		}

		if err != nil {
			log.Printf("警告：未找到SSL库，将只监控HTTP流量: %v", err)
		} else {
			log.Println("正在附加SSL uprobe程序...")
			sslLinks, err = attachSSLUprobes(coll, libsslPath)
			if err != nil {
				log.Printf("警告：附加SSL uprobe失败，将只监控HTTP流量: %v", err)
			} else {
				log.Println("✓ SSL uprobe程序附加成功")
				log.Println("现在可以监控HTTPS流量了")
			}
		}
	} else {
		log.Println("SSL uprobe程序未找到，将只监控HTTP流量")
	}

	// 创建HTTP监控器
	monitor, err := http.NewHTTPMonitor(coll, filterConfig, *parseBody)
	if err != nil {
		log.Fatalf("创建HTTP监控器失败: %v", err)
	}
	defer monitor.Stop()

	// 清理SSL links
	defer func() {
		for _, l := range sslLinks {
			if err := l.Close(); err != nil {
				log.Printf("关闭SSL link失败: %v", err)
			}
		}
	}()

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理中断信号
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt, shutting down...")
		cancel()
	}()

	// 启动HTTP监控
	monitor.Start(ctx)

	// 等待上下文取消
	<-ctx.Done()
	fmt.Println("HTTP监控已停止")
}
