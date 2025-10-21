package http

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// HTTPEvent HTTP/HTTPS事件结构
type HTTPEvent struct {
	// 基础网络信息
	SrcAddr  uint32
	DstAddr  uint32
	IPProto  uint32
	DstMac   [6]uint8
	TTL      uint8
	IfIndex  uint32
	SrcPort  uint16
	DstPort  uint16
	TcpFlags uint8
	TcpSeq   uint32
	TcpAck   uint32
	TcpLen   uint16
	UdpLen   uint16
	FuncName [32]byte

	// HTTP/HTTPS特有字段
	HTTPVersion   uint8
	Method        [16]byte
	RequestUri    [256]byte
	RequestParams [512]byte
	StatusCode    uint16
	BodyLen       uint16
	ResponseBody  [1024]byte
	RW            uint8
	TimestampNs   uint64
}

// GetSourceIP 获取源IP地址字符串
func (e *HTTPEvent) GetSourceIP() string {
	return IntToIP(e.SrcAddr)
}

// GetDestinationIP 获取目标IP地址字符串
func (e *HTTPEvent) GetDestinationIP() string {
	return IntToIP(e.DstAddr)
}

// GetProtocolName 获取协议名称
func (e *HTTPEvent) GetProtocolName() string {
	return "HTTP"
}

// GetTimestamp 获取当前时间戳字符串
func (e *HTTPEvent) GetTimestamp() string {
	return time.Unix(0, int64(e.TimestampNs)).Format("15:04:05.000")
}

// GetMethod 获取HTTP方法字符串
func (e *HTTPEvent) GetMethod() string {
	return strings.TrimRight(string(e.Method[:]), "\x00")
}

// GetRequestUri 获取请求URI字符串
func (e *HTTPEvent) GetRequestUri() string {
	return strings.TrimRight(string(e.RequestUri[:]), "\x00")
}

// GetRequestParams 获取请求参数字符串
func (e *HTTPEvent) GetRequestParams() string {
	return strings.TrimRight(string(e.RequestParams[:]), "\x00")
}

// GetResponseBody 获取响应体字符串
func (e *HTTPEvent) GetResponseBody() string {
	return strings.TrimRight(string(e.ResponseBody[:]), "\x00")
}

// GetStatusCode 获取HTTP状态码
func (e *HTTPEvent) GetStatusCode() uint16 {
	return e.StatusCode
}

// GetBodyLength 获取响应体长度
func (e *HTTPEvent) GetBodyLength() int {
	return int(e.BodyLen)
}

// IsHTTPS 判断是否为HTTPS
func (e *HTTPEvent) IsHTTPS() bool {
	// 通过端口判断
	if e.DstPort == 443 || e.SrcPort == 443 {
		return true
	}

	// 通过方法名判断（eBPF中设置的"HTTPS"标识）
	method := e.GetMethod()
	if method == "HTTPS" {
		return true
	}

	return false
}

// FormatEventInfo 格式化事件信息为字符串
func (e *HTTPEvent) FormatEventInfo() string {
	// 构建Info字段，采用与现有网络监控一致的格式
	info := fmt.Sprintf("%d->%d",
		e.SrcPort, e.DstPort)

	// 添加HTTP方法（如果不是HTTPS标识）
	method := e.GetMethod()
	if method != "HTTPS" && method != "" {
		uri := e.GetRequestUri()
		if uri != "" {
			info += fmt.Sprintf(" %s %s", method, uri)
		} else {
			info += fmt.Sprintf(" %s", method)
		}
	}

	// 添加请求参数（如果有）
	params := e.GetRequestParams()
	if len(params) > 0 && params != "{}" {
		info += fmt.Sprintf(" params:%s", params)
	}

	// 添加请求体或响应体（如果启用）
	if e.BodyLen > 0 {
		body := e.GetResponseBody()
		if len(body) > 0 {
			// 对于HTTPS，显示加密数据的前几个字节
			if e.IsHTTPS() {
				// 限制显示长度，避免输出过长
				maxLen := 50
				if len(body) > maxLen {
					body = body[:maxLen] + "..."
				}
				info += fmt.Sprintf(" encryptedData:%s", body)
			} else {
				// 对于HTTP，根据RW字段判断是请求还是响应
				if e.RW == 0 {
					// RW=0 表示读取，即响应
					info += fmt.Sprintf(" responseBody:%s", body)
				} else {
					// RW=1 表示写入，即请求
					info += fmt.Sprintf(" requestBody:%s", body)
				}
			}
		}
	}

	return info
}

// IntToIP converts a uint32 IP address to string
func IntToIP(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

// MacToString converts a MAC address array to string
func MacToString(mac [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
