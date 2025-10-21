package http

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

// HTTPFilterConfig 独立HTTP过滤配置结构
type HTTPFilterConfig struct {
	// 网络层过滤字段
	SrcHost uint32
	DstHost uint32
	Host    uint32
	DstPort uint16
	SrcPort uint16
	Port    uint16

	// HTTP/HTTPS过滤字段
	ParseBody  bool   // 是否解析响应体
	HTTPMethod string // HTTP方法过滤
	HTTPStatus uint16 // HTTP状态码过滤
	HTTPUri    string // HTTP URI过滤
}

// ParseHTTPFilterConfig 独立HTTP过滤配置解析函数
func ParseHTTPFilterConfig(srcHostStr, dstHostStr, hostStr string,
	dstPort, srcPort, port int,
	httpMethod string, httpStatus int, httpUri string) (*HTTPFilterConfig, error) {
	config := &HTTPFilterConfig{}

	// 解析网络层过滤
	if srcHostStr != "" {
		ip := net.ParseIP(srcHostStr)
		if ip == nil {
			return nil, fmt.Errorf("无效的来源主机地址: %s", srcHostStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("只支持IPv4地址: %s", srcHostStr)
		}
		config.SrcHost = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	}

	if dstHostStr != "" {
		ip := net.ParseIP(dstHostStr)
		if ip == nil {
			return nil, fmt.Errorf("无效的目标主机地址: %s", dstHostStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("只支持IPv4地址: %s", dstHostStr)
		}
		config.DstHost = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	}

	if hostStr != "" {
		ip := net.ParseIP(hostStr)
		if ip == nil {
			return nil, fmt.Errorf("无效的主机地址: %s", hostStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("只支持IPv4地址: %s", hostStr)
		}
		config.Host = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	}

	config.DstPort = uint16(dstPort)
	config.SrcPort = uint16(srcPort)
	config.Port = uint16(port)

	// 解析HTTP方法过滤
	if httpMethod != "" {
		httpMethod = strings.ToUpper(strings.TrimSpace(httpMethod))
		validMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
		valid := false
		for _, method := range validMethods {
			if httpMethod == method {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("不支持的HTTP方法: %s", httpMethod)
		}
		config.HTTPMethod = httpMethod
	}

	// 解析HTTP状态码过滤
	if httpStatus < 0 || httpStatus > 599 {
		return nil, fmt.Errorf("无效的HTTP状态码: %d", httpStatus)
	}
	config.HTTPStatus = uint16(httpStatus)

	// 解析HTTP URI过滤
	if httpUri != "" {
		config.HTTPUri = strings.TrimSpace(httpUri)
		// 支持通配符匹配，如 /api/*, /user/*/profile
	}

	return config, nil
}

// SetHTTPFilterConfig 独立HTTP过滤配置设置函数
func SetHTTPFilterConfig(coll *ebpf.Collection, config *HTTPFilterConfig) error {
	// 设置网络层过滤
	filterMap := coll.Maps["filter_config"]
	if filterMap != nil {
		// 设置来源主机过滤 (key=0)
		if config.SrcHost != 0 {
			key := uint32(0)
			if err := filterMap.Put(key, config.SrcHost); err != nil {
				return fmt.Errorf("设置来源主机过滤失败: %v", err)
			}
		}

		// 设置目标主机过滤 (key=5)
		if config.DstHost != 0 {
			key := uint32(5)
			if err := filterMap.Put(key, config.DstHost); err != nil {
				return fmt.Errorf("设置目标主机过滤失败: %v", err)
			}
		}

		// 设置主机过滤 (key=6)
		if config.Host != 0 {
			key := uint32(6)
			if err := filterMap.Put(key, config.Host); err != nil {
				return fmt.Errorf("设置主机过滤失败: %v", err)
			}
		}

		// 设置目的端口过滤 (key=2)
		if config.DstPort != 0 {
			key := uint32(2)
			if err := filterMap.Put(key, uint32(config.DstPort)); err != nil {
				return fmt.Errorf("设置目的端口过滤失败: %v", err)
			}
		}

		// 设置来源端口过滤 (key=3)
		if config.SrcPort != 0 {
			key := uint32(3)
			if err := filterMap.Put(key, uint32(config.SrcPort)); err != nil {
				return fmt.Errorf("设置来源端口过滤失败: %v", err)
			}
		}

		// 设置端口过滤 (key=4)
		if config.Port != 0 {
			key := uint32(4)
			if err := filterMap.Put(key, uint32(config.Port)); err != nil {
				return fmt.Errorf("设置端口过滤失败: %v", err)
			}
		}
	}

	// 设置HTTP层过滤
	httpFilterMap := coll.Maps["http_filter_config"]
	if httpFilterMap != nil {
		// 设置HTTP方法过滤 (key=11)
		if config.HTTPMethod != "" {
			key := uint32(11)
			value := stringToHTTPMethod(config.HTTPMethod)
			if err := httpFilterMap.Put(key, value); err != nil {
				return fmt.Errorf("设置HTTP方法过滤失败: %v", err)
			}
		}

		// 设置HTTP状态码过滤 (key=12)
		if config.HTTPStatus != 0 {
			key := uint32(12)
			if err := httpFilterMap.Put(key, uint32(config.HTTPStatus)); err != nil {
				return fmt.Errorf("设置HTTP状态码过滤失败: %v", err)
			}
		}

		// 设置HTTP URI过滤 (key=13)
		if config.HTTPUri != "" {
			key := uint32(13)
			// 将URI字符串转换为哈希值进行匹配
			value := hashString(config.HTTPUri)
			if err := httpFilterMap.Put(key, value); err != nil {
				return fmt.Errorf("设置HTTP URI过滤失败: %v", err)
			}
		}
	}

	return nil
}

// stringToHTTPMethod HTTP方法字符串转数字
func stringToHTTPMethod(method string) uint32 {
	switch method {
	case "GET":
		return 1
	case "POST":
		return 2
	case "PUT":
		return 3
	case "DELETE":
		return 4
	case "HEAD":
		return 5
	case "OPTIONS":
		return 6
	case "PATCH":
		return 7
	case "TRACE":
		return 8
	case "CONNECT":
		return 9
	default:
		return 0
	}
}

// hashString 字符串哈希函数
func hashString(s string) uint32 {
	hash := uint32(0)
	for _, c := range s {
		hash = hash*31 + uint32(c)
	}
	return hash
}
