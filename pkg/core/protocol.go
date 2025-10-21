package core

import (
	"fmt"
	"net"
	"strings"
)

// Protocol numbers
const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolGRE  = 47
	ProtocolESP  = 50
	ProtocolAH   = 51
	ProtocolOSPF = 89
	ProtocolSCTP = 132
)

// GetProtocolName returns the protocol name for a given protocol number
func GetProtocolName(proto uint32) string {
	switch proto {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolGRE:
		return "GRE"
	case ProtocolESP:
		return "ESP"
	case ProtocolAH:
		return "AH"
	case ProtocolOSPF:
		return "OSPF"
	case ProtocolSCTP:
		return "SCTP"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}

// IntToIP converts a uint32 IP address to string
// Note: eBPF program already calls bpf_ntohl() to convert to network byte order
func IntToIP(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

// MacToString converts a MAC address array to string
func MacToString(mac [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// IfIndexToName converts interface index to interface name
func IfIndexToName(ifIndex uint32) string {
	if ifIndex == 0 {
		return ""
	}
	
	// 对于异常大的索引值，直接返回数字形式
	if ifIndex > 1000000 {
		return fmt.Sprintf("if%d(invalid)", ifIndex)
	}
	
	// 使用 net.InterfaceByIndex 获取接口名称
	iface, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		// 如果无法解析，显示索引号
		return fmt.Sprintf("if%d", ifIndex)
	}
	return iface.Name
}

// GetTcpFlagsString returns a string representation of TCP flags
func GetTcpFlagsString(flags uint8) string {
	var flagStrs []string
	
	if flags&0x01 != 0 { // FIN
		flagStrs = append(flagStrs, "FIN")
	}
	if flags&0x02 != 0 { // SYN
		flagStrs = append(flagStrs, "SYN")
	}
	if flags&0x04 != 0 { // RST
		flagStrs = append(flagStrs, "RST")
	}
	if flags&0x08 != 0 { // PSH
		flagStrs = append(flagStrs, "PSH")
	}
	if flags&0x10 != 0 { // ACK
		flagStrs = append(flagStrs, "ACK")
	}
	if flags&0x20 != 0 { // URG
		flagStrs = append(flagStrs, "URG")
	}
	if flags&0x40 != 0 { // ECE
		flagStrs = append(flagStrs, "ECE")
	}
	if flags&0x80 != 0 { // CWR
		flagStrs = append(flagStrs, "CWR")
	}
	
	if len(flagStrs) == 0 {
		return "NONE"
	}
	
	return strings.Join(flagStrs, ",")
}

// ParseProtocolString parses protocol string to protocol number
func ParseProtocolString(proto string) (uint32, error) {
	proto = strings.TrimSpace(strings.ToLower(proto))
	switch proto {
	case "tcp":
		return ProtocolTCP, nil
	case "udp":
		return ProtocolUDP, nil
	case "icmp":
		return ProtocolICMP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}
