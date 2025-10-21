package color

import (
	"fmt"
	"netbee/pkg/core"
)

// ColorManager 颜色管理器
type ColorManager struct {
	config    *Config
	formatter *ColorFormatter
	detector  *TerminalDetector
}

// NewColorManager 创建颜色管理器
func NewColorManager(noColor bool, forceColor bool) *ColorManager {
	config := NewConfig(noColor, forceColor)
	formatter := NewColorFormatter(config.Enabled)
	detector := &TerminalDetector{}

	return &ColorManager{
		config:    config,
		formatter: formatter,
		detector:  detector,
	}
}

// FormatEvent 格式化事件
func (cm *ColorManager) FormatEvent(event *core.SoEvent, symbolResolver *core.SymbolResolver) *FormattedEvent {
	return &FormattedEvent{
		Time:     event.GetTimestamp(),
		SrcIP:    event.GetSourceIP(),
		DstIP:    event.GetDestinationIP(),
		Protocol: event.GetProtocolName(),
		Length:   event.GetDataLength(),
		SrcMAC:   cm.formatter.FormatMAC(event),
		TTL:      cm.formatter.FormatTTL(event),
		Info:     cm.formatter.FormatInfo(event, symbolResolver),
	}
}

// FormattedEvent 格式化后的事件
type FormattedEvent struct {
	Time     string
	SrcIP    string
	DstIP    string
	Protocol string
	Length   int
	SrcMAC   string
	TTL      string
	Info     string
}

// Print 打印格式化事件
func (fe *FormattedEvent) Print() {
	fmt.Printf("%-20s %-15s %-15s %-8s %-6d %-17s %-3s %-20s\n",
		fe.Time, fe.SrcIP, fe.DstIP, fe.Protocol, fe.Length, fe.SrcMAC, fe.TTL, fe.Info)
}

// IsEnabled 检查颜色是否启用
func (cm *ColorManager) IsEnabled() bool {
	return cm.config.Enabled
}

// GetConfig 获取配置
func (cm *ColorManager) GetConfig() *Config {
	return cm.config
}
