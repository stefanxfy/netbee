package http

import (
	"context"
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// HTTPMonitor HTTP监控器
type HTTPMonitor struct {
	rb           *ringbuf.Reader
	filterConfig *HTTPFilterConfig
	parseBody    bool
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewHTTPMonitor 创建HTTP监控器实例
func NewHTTPMonitor(coll *ebpf.Collection, config *HTTPFilterConfig, parseBody bool) (*HTTPMonitor, error) {
	// 创建HTTP事件ring buffer reader
	rb, err := ringbuf.NewReader(coll.Maps["http_events"])
	if err != nil {
		return nil, fmt.Errorf("Failed to create HTTP ring buffer reader: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &HTTPMonitor{
		rb:           rb,
		filterConfig: config,
		parseBody:    parseBody,
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Start 启动HTTP监控
func (hm *HTTPMonitor) Start(ctx context.Context) {
	go hm.monitorHTTPEvents(ctx)
}

// Stop 停止HTTP监控
func (hm *HTTPMonitor) Stop() {
	hm.cancel()
	hm.rb.Close()
}

// monitorHTTPEvents HTTP事件监控循环
func (hm *HTTPMonitor) monitorHTTPEvents(ctx context.Context) {
	log.Println("开始监控HTTP数据包...")

	// 输出字段名标题行
	fmt.Printf("%-20s %-15s %-15s %-8s %-6s %-3s %-20s\n",
		"Time", "SrcIP", "DstIP", "Protocol", "Length", "TTL", "Info")
	fmt.Printf("%-20s %-15s %-15s %-8s %-6s %-3s %-20s\n",
		"----", "-----", "-----", "--------", "------", "---", "----")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := hm.rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Error reading from HTTP ring buffer: %v", err)
				continue
			}

			// 解析HTTP事件
			var event HTTPEvent
			if len(record.RawSample) < int(unsafe.Sizeof(event)) {
				log.Printf("HTTP event data too short: %d bytes", len(record.RawSample))
				continue
			}

			// 复制数据直接从RawSample
			event = *(*HTTPEvent)(unsafe.Pointer(&record.RawSample[0]))

			// 处理HTTP事件
			hm.handleHTTPEvent(&event)
		}
	}
}

// handleHTTPEvent HTTP事件处理函数
func (hm *HTTPMonitor) handleHTTPEvent(event *HTTPEvent) {
	// 应用HTTP特定过滤
	if !hm.applyHTTPFilters(event) {
		return
	}

	// 格式化输出HTTP事件
	hm.formatHTTPOutput(event)
}

// applyHTTPFilters HTTP过滤逻辑
func (hm *HTTPMonitor) applyHTTPFilters(event *HTTPEvent) bool {
	// 方法过滤
	if hm.filterConfig.HTTPMethod != "" {
		if event.GetMethod() != hm.filterConfig.HTTPMethod {
			return false
		}
	}

	// 状态码过滤
	if hm.filterConfig.HTTPStatus != 0 {
		if event.StatusCode != hm.filterConfig.HTTPStatus {
			return false
		}
	}

	// URI过滤
	if hm.filterConfig.HTTPUri != "" {
		uri := event.GetRequestUri()
		if !hm.matchURI(uri, hm.filterConfig.HTTPUri) {
			return false
		}
	}

	return true
}

// matchURI URI匹配函数，支持通配符
func (hm *HTTPMonitor) matchURI(uri, pattern string) bool {
	// 简单的通配符匹配实现
	if pattern == "*" {
		return true
	}

	// 检查是否以通配符结尾
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(uri) >= len(prefix) && uri[:len(prefix)] == prefix
	}

	// 精确匹配
	return uri == pattern
}

// formatHTTPOutput 格式化HTTP事件输出
func (hm *HTTPMonitor) formatHTTPOutput(event *HTTPEvent) {
	// 格式化时间戳
	timestamp := event.GetTimestamp()

	// 确定协议类型
	protocol := "http"
	if event.IsHTTPS() {
		protocol = "https"
	}

	// 获取信息字符串
	infoStr := event.FormatEventInfo()

	// 输出表格格式的数据
	fmt.Printf("%-20s %-15s %-15s %-8s %-6d %-3d %-20s\n",
		timestamp,
		event.GetSourceIP(),
		event.GetDestinationIP(),
		protocol,
		event.GetBodyLength(),
		event.TTL,
		infoStr)
}
