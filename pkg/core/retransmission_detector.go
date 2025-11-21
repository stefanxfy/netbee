package core

import (
	"sync"
)

// TCPPacketKey TCP 数据包的唯一标识键
// 注意：为了识别跨端口的重传（例如应用使用不同源端口重试），
// 我们只使用 SrcIP, DstIP, Seq, Ack 作为键，忽略端口信息
type TCPPacketKey struct {
	SrcIP uint32
	DstIP uint32
	Seq   uint32
	Ack   uint32
}

// RetransmissionDetector 重传检测器
type RetransmissionDetector struct {
	mu              sync.RWMutex
	seen            map[TCPPacketKey]int // 记录每个包出现的次数
	cleanupInterval int                  // 清理间隔（记录数）
	recordCount     int                  // 当前记录数
}

// NewRetransmissionDetector 创建重传检测器
func NewRetransmissionDetector() *RetransmissionDetector {
	return &RetransmissionDetector{
		seen:            make(map[TCPPacketKey]int),
		cleanupInterval: 10000, // 每10000条记录清理一次
		recordCount:     0,
	}
}

// IsRetransmission 检测是否为重传包
// 返回 true 表示是重传包，false 表示是首次出现的包
func (rd *RetransmissionDetector) IsRetransmission(event *SoEvent) bool {
	// 只检测 TCP 包
	if event.IPProto != ProtocolTCP {
		return false
	}

	// 构建唯一键（忽略端口，只使用 IP 和 Seq/Ack）
	// 这样可以识别跨端口的重传，例如应用使用不同源端口重试连接
	key := TCPPacketKey{
		SrcIP: event.SrcAddr,
		DstIP: event.DstAddr,
		Seq:   event.TcpSeq,
		Ack:   event.TcpAck,
	}

	rd.mu.Lock()
	defer rd.mu.Unlock()

	// 检查是否已见过
	count, exists := rd.seen[key]
	if exists {
		// 已见过，是重传包
		rd.seen[key] = count + 1
		rd.recordCount++

		// 定期清理，避免内存泄漏
		if rd.recordCount >= rd.cleanupInterval {
			rd.cleanup()
			rd.recordCount = 0
		}

		return true
	}

	// 首次出现，记录
	rd.seen[key] = 1
	rd.recordCount++

	// 定期清理
	if rd.recordCount >= rd.cleanupInterval {
		rd.cleanup()
		rd.recordCount = 0
	}

	return false
}

// cleanup 清理旧的记录（保留最近出现的记录）
// 简单的清理策略：删除出现次数为1的记录（可能是旧的首次包）
func (rd *RetransmissionDetector) cleanup() {
	// 清理策略：如果记录数过多，删除一些旧的记录
	// 这里使用简单的策略：如果 map 太大，清空一半
	if len(rd.seen) > 50000 {
		// 清空 map，重新开始
		rd.seen = make(map[TCPPacketKey]int)
	}
}

// Reset 重置检测器
func (rd *RetransmissionDetector) Reset() {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.seen = make(map[TCPPacketKey]int)
	rd.recordCount = 0
}
