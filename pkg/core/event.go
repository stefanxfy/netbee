package core

import (
	"fmt"
	"strings"
	"time"
)

// SoEvent represents the network packet event structure sent from eBPF program
type SoEvent struct {
	SrcAddr uint32
	DstAddr uint32
	IPProto uint32
	SrcMac  [6]uint8
	DstMac  [6]uint8
	TTL     uint8
	IfIndex uint32
	SrcPort uint16
	DstPort uint16
	// TCP相关字段
	TcpFlags uint8
	TcpSeq   uint32
	TcpAck   uint32
	TcpLen   uint16
	// UDP相关字段
	UdpLen     uint16
	FuncName   [32]byte
	Pid        uint32
	StackTrace [64]uint64
	StackDepth uint32

	// 新增：Netfilter 相关字段
	NFHook  uint8 // Netfilter 钩子点 (NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, 等)
	Verdict int8  // 处理结果 (1=OKFN_NEEDED, -1=DROP, 0=OTHER)
}

// FormatEventInfo 格式化事件信息为字符串
func (e *SoEvent) FormatEventInfo(symbolResolver *SymbolResolver) string {
	// 获取调用栈信息
	stackInfo := FormatStackTrace(e.StackTrace, e.StackDepth, symbolResolver)

	// 检查是否有 Netfilter 信息
	var nfInfo string
	if e.NFHook != 0 || e.Verdict != 0 {
		nfInfo = " NF:" + FormatNFInfo(e.NFHook, e.Verdict)
	}

	// 获取接口名称
	ifaceName := IfIndexToName(e.IfIndex)

	// 获取函数名
	funcName := e.GetFunctionName()

	if e.IPProto == ProtocolTCP {
		tcpFlags := GetTcpFlagsString(e.TcpFlags)
		return fmt.Sprintf("%d->%d %s Seq:%d Ack:%d %s [%s] PID:%d%s%s",
			e.SrcPort, e.DstPort, tcpFlags, e.TcpSeq, e.TcpAck, ifaceName, funcName, e.Pid, stackInfo, nfInfo)
	} else if e.IPProto == ProtocolUDP {
		return fmt.Sprintf("%d->%d %s [%s] PID:%d%s%s",
			e.SrcPort, e.DstPort, ifaceName, funcName, e.Pid, stackInfo, nfInfo)
	} else {
		protocol := GetProtocolName(e.IPProto)
		return fmt.Sprintf("%s %s [%s] PID:%d%s%s", protocol, ifaceName, funcName, e.Pid, stackInfo, nfInfo)
	}
}

// GetDataLength 获取数据包数据长度
func (e *SoEvent) GetDataLength() int {
	if e.IPProto == ProtocolTCP {
		return int(e.TcpLen)
	} else if e.IPProto == ProtocolUDP {
		return int(e.UdpLen)
	}
	return 0
}

// GetSourceIP 获取源IP地址字符串
func (e *SoEvent) GetSourceIP() string {
	return IntToIP(e.SrcAddr)
}

// GetDestinationIP 获取目标IP地址字符串
func (e *SoEvent) GetDestinationIP() string {
	return IntToIP(e.DstAddr)
}

// GetSourceMAC 获取源MAC地址字符串
func (e *SoEvent) GetSourceMAC() string {
	return MacToString(e.SrcMac)
}

// GetSourceMACWithVendor 获取源MAC地址字符串（包含厂商名称）
func (e *SoEvent) GetSourceMACWithVendor() string {
	resolver, err := GetMacResolver()
	if err != nil {
		// 如果解析器初始化失败，返回普通MAC地址
		return MacToString(e.SrcMac)
	}
	return resolver.ResolveMacAddress(e.SrcMac)
}

// GetProtocolName 获取协议名称
func (e *SoEvent) GetProtocolName() string {
	return GetProtocolName(e.IPProto)
}

// GetInterfaceName 获取网络接口名称
func (e *SoEvent) GetInterfaceName() string {
	return IfIndexToName(e.IfIndex)
}

// GetFunctionName 获取函数名称
func (e *SoEvent) GetFunctionName() string {
	// 找到第一个null终止符的位置
	nullIndex := -1
	for i, b := range e.FuncName {
		if b == 0 {
			nullIndex = i
			break
		}
	}

	// 如果没有找到null终止符，使用整个数组
	if nullIndex == -1 {
		nullIndex = len(e.FuncName)
	}

	// 提取有效的函数名部分
	funcName := string(e.FuncName[:nullIndex])

	// 移除任何非打印字符（除了字母、数字、下划线、连字符）
	var cleanName strings.Builder
	for _, r := range funcName {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			cleanName.WriteRune(r)
		} else {
			// 遇到非打印字符就停止
			break
		}
	}

	return cleanName.String()
}

// GetTimestamp 获取当前时间戳字符串
func (e *SoEvent) GetTimestamp() string {
	now := time.Now()
	return now.Format("15:04:05.000")
}

// HasNetfilterInfo 检查是否有 Netfilter 信息
func (e *SoEvent) HasNetfilterInfo() bool {
	return e.NFHook != 0 || e.Verdict != 0
}

// GetNetfilterInfo 获取 Netfilter 信息字符串
func (e *SoEvent) GetNetfilterInfo() string {
	if e.HasNetfilterInfo() {
		return " NF:" + FormatNFInfo(e.NFHook, e.Verdict)
	}
	return ""
}
