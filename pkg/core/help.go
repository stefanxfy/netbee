package core

import "fmt"

// ShowSimpleHelp 显示简化的帮助信息（用于 -h 参数）
func ShowSimpleHelp() {
	fmt.Println("网络数据包监控工具 - netbee")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  sudo ./target/netbee [选项]")
	fmt.Println()

	// 协议过滤参数
	fmt.Println("协议过滤 (proto):")
	fmt.Println("  -proto string")
	fmt.Println("        过滤协议，逗号分隔 (tcp,udp,icmp)")
	fmt.Println()

	// 主机过滤参数
	fmt.Println("主机过滤 (host):")
	fmt.Println("  -shost string")
	fmt.Println("        过滤来源主机IP地址")
	fmt.Println("  -dhost string")
	fmt.Println("        过滤目标主机IP地址")
	fmt.Println("  -host string")
	fmt.Println("        过滤主机IP地址 (来源或目标IP匹配即可)")
	fmt.Println()

	// 端口过滤参数
	fmt.Println("端口过滤 (port):")
	fmt.Println("  -sport int")
	fmt.Println("        过滤来源端口")
	fmt.Println("  -dport int")
	fmt.Println("        过滤目的端口")
	fmt.Println("  -port int")
	fmt.Println("        过滤端口 (来源端口或目的端口匹配即可)")
	fmt.Println()

	// 调试参数
	fmt.Println("调试选项 (kfree):")
	fmt.Println("  -kfree")
	fmt.Println("        显示kfree_skb的调用栈信息")
	fmt.Println()

	// 颜色输出选项
	fmt.Println("颜色输出选项:")
	fmt.Println("  -no-color")
	fmt.Println("        禁用颜色输出")
	fmt.Println()

	// 包数量控制选项
	fmt.Println("包数量控制:")
	fmt.Println("  -c int")
	fmt.Println("        捕获指定数量的数据包后自动退出")
	fmt.Println("        示例: -c 100")
	fmt.Println()

	// 帮助参数
	fmt.Println("其他选项:")
	fmt.Println("  -help")
	fmt.Println("        显示详细帮助信息（包含使用示例）")
}

// ShowHelp 显示帮助信息
func ShowHelp() {
	fmt.Println("网络数据包监控工具 - netbee")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  sudo ./target/netbee [选项]")
	fmt.Println()

	// 协议过滤参数
	fmt.Println("协议过滤 (proto):")
	fmt.Println("  -proto string")
	fmt.Println("        过滤协议，逗号分隔 (tcp,udp,icmp)")
	fmt.Println("        示例: -proto tcp,udp")
	fmt.Println("        示例: -proto icmp")
	fmt.Println()

	// 主机过滤参数
	fmt.Println("主机过滤 (host):")
	fmt.Println("  -shost string")
	fmt.Println("        过滤来源主机IP地址")
	fmt.Println("        示例: -shost 192.168.1.1")
	fmt.Println("  -dhost string")
	fmt.Println("        过滤目标主机IP地址")
	fmt.Println("        示例: -dhost 8.8.8.8")
	fmt.Println("  -host string")
	fmt.Println("        过滤主机IP地址 (来源或目标IP匹配即可)")
	fmt.Println("        示例: -host 10.0.0.1")
	fmt.Println()

	// 端口过滤参数
	fmt.Println("端口过滤 (port):")
	fmt.Println("  -sport int")
	fmt.Println("        过滤来源端口")
	fmt.Println("        示例: -sport 8080")
	fmt.Println("  -dport int")
	fmt.Println("        过滤目的端口")
	fmt.Println("        示例: -dport 80")
	fmt.Println("  -port int")
	fmt.Println("        过滤端口 (来源端口或目的端口匹配即可)")
	fmt.Println("        示例: -port 80")
	fmt.Println()

	// 调试参数
	fmt.Println("调试选项 (kfree):")
	fmt.Println("  -kfree")
	fmt.Println("        显示kfree_skb的调用栈信息")
	fmt.Println("        用于调试数据包丢弃原因")
	fmt.Println()

	// 颜色输出选项
	fmt.Println("颜色输出选项:")
	fmt.Println("  -no-color")
	fmt.Println("        禁用颜色输出")
	fmt.Println("        默认启用颜色：RST标志显示红色，TTL>100显示黄色，MAC厂商名称显示黄色")
	fmt.Println()

	// 包数量控制选项
	fmt.Println("包数量控制:")
	fmt.Println("  -c int")
	fmt.Println("        捕获指定数量的数据包后自动退出")
	fmt.Println("        示例: -c 100")
	fmt.Println()

	// 使用示例
	fmt.Println("使用示例:")
	fmt.Println("  # 监控所有TCP和UDP流量")
	fmt.Println("  sudo ./target/netbee -proto tcp,udp")
	fmt.Println()
	fmt.Println("  # 监控特定主机的ICMP流量")
	fmt.Println("  sudo ./target/netbee -host 8.8.8.8 -proto icmp")
	fmt.Println()
	fmt.Println("  # 监控HTTP流量 (端口80)")
	fmt.Println("  sudo ./target/netbee -proto tcp -dport 80")
	fmt.Println()
	fmt.Println("  # 监控特定来源主机的所有流量")
	fmt.Println("  sudo ./target/netbee -shost 192.168.1.100")
	fmt.Println()
	fmt.Println("  # 调试数据包丢弃 (显示调用栈)")
	fmt.Println("  sudo ./target/netbee -kfree")
	fmt.Println()
	fmt.Println("  # 组合过滤: 监控特定主机到特定端口的TCP流量")
	fmt.Println("  sudo ./target/netbee -shost 192.168.1.1 -dport 80 -proto tcp")
	fmt.Println()
	fmt.Println("  # 捕获100个数据包后自动退出")
	fmt.Println("  sudo ./target/netbee -c 100")
	fmt.Println()
	fmt.Println("  # 禁用颜色输出")
	fmt.Println("  sudo ./target/netbee -no-color")
}
