package core

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"github.com/cilium/ebpf"
)

// FilterConfig 存储过滤配置
type FilterConfig struct {
	SrcHostStr   string
	SrcHost      uint32
	DstHostStr   string
	DstHost      uint32
	HostStr      string
	Host         uint32
	Protocols    []string
	ProtocolNums []uint32
	DstPort      uint16
	SrcPort      uint16
	Port         uint16
}

// ParseFilterConfig 解析过滤配置
func ParseFilterConfig(srcHostStr, dstHostStr, hostStr, protocolsStr string, dstPort, srcPort, port int) (*FilterConfig, error) {
	// 处理空协议字符串
	var protocols []string
	if protocolsStr != "" {
		protocols = strings.Split(protocolsStr, ",")
	}
	
	config := &FilterConfig{
		SrcHostStr: srcHostStr,
		DstHostStr: dstHostStr,
		HostStr:    hostStr,
		Protocols:  protocols,
		DstPort:    uint16(dstPort),
		SrcPort:    uint16(srcPort),
		Port:       uint16(port),
	}

	// 解析来源主机
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

	// 解析目标主机
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

	// 解析主机
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

	// 解析协议
	for _, proto := range config.Protocols {
		proto = strings.TrimSpace(strings.ToLower(proto))
		var protoNum uint32
		switch proto {
		case "tcp":
			protoNum = ProtocolTCP
		case "udp":
			protoNum = ProtocolUDP
		case "icmp":
			protoNum = ProtocolICMP
		default:
			// 尝试解析为数字
			if num, err := strconv.ParseUint(proto, 10, 32); err == nil {
				protoNum = uint32(num)
			} else {
				return nil, fmt.Errorf("不支持的协议: %s", proto)
			}
		}
		config.ProtocolNums = append(config.ProtocolNums, protoNum)
	}

	return config, nil
}

// SetFilterConfig 设置eBPF过滤配置和kfree配置
func SetFilterConfig(coll *ebpf.Collection, config *FilterConfig, kfreeEnabled bool) error {
	// 设置过滤配置
	filterMap := coll.Maps["filter_config"]
	if filterMap == nil {
		return fmt.Errorf("filter_config map not found")
	}

	// 设置来源主机过滤
	if config.SrcHost != 0 {
		key := uint32(0)
		if err := filterMap.Put(key, config.SrcHost); err != nil {
			return fmt.Errorf("设置来源主机过滤失败: %v", err)
		}
	}

	// 设置目标主机过滤
	if config.DstHost != 0 {
		key := uint32(5)
		if err := filterMap.Put(key, config.DstHost); err != nil {
			return fmt.Errorf("设置目标主机过滤失败: %v", err)
		}
	}

	// 设置主机过滤（来源或目标主机匹配）
	if config.Host != 0 {
		key := uint32(6)
		if err := filterMap.Put(key, config.Host); err != nil {
			return fmt.Errorf("设置主机过滤失败: %v", err)
		}
	}

	// 设置协议过滤（目前只支持单个协议）
	if len(config.ProtocolNums) > 0 {
		key := uint32(1)
		// 使用第一个协议作为过滤条件
		if err := filterMap.Put(key, config.ProtocolNums[0]); err != nil {
			return fmt.Errorf("设置协议过滤失败: %v", err)
		}
	}

	// 设置目的端口过滤
	if config.DstPort != 0 {
		key := uint32(2)
		if err := filterMap.Put(key, uint32(config.DstPort)); err != nil {
			return fmt.Errorf("设置目的端口过滤失败: %v", err)
		}
	}

	// 设置来源端口过滤
	if config.SrcPort != 0 {
		key := uint32(3)
		if err := filterMap.Put(key, uint32(config.SrcPort)); err != nil {
			return fmt.Errorf("设置来源端口过滤失败: %v", err)
		}
	}

	// 设置端口过滤（来源端口或目的端口匹配）
	if config.Port != 0 {
		key := uint32(4)
		if err := filterMap.Put(key, uint32(config.Port)); err != nil {
			return fmt.Errorf("设置端口过滤失败: %v", err)
		}
	}

	// 设置kfree配置
	kfreeConfigMap := coll.Maps["kfree_config"]
	if kfreeConfigMap != nil {
		kfreeKey := uint32(0)
		kfreeValue := uint32(0)
		if kfreeEnabled {
			kfreeValue = 1
		}
		if err := kfreeConfigMap.Put(kfreeKey, kfreeValue); err != nil {
			log.Printf("Warning: Failed to set kfree config: %v\n", err)
		} else {
			log.Printf("Kfree stack trace enabled: %v\n", kfreeEnabled)
		}
	}

	return nil
}
