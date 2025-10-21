package color

import (
	"netbee/pkg/core"
	"strings"
)

// ColorRule 颜色规则接口
type ColorRule interface {
	Name() string
	ShouldApply(event *core.SoEvent) bool
	GetColor() Color
	GetText(event *core.SoEvent) string
}

// RSTColorRule RST标志红色规则
type RSTColorRule struct{}

func (r *RSTColorRule) Name() string { return "RST" }

func (r *RSTColorRule) ShouldApply(event *core.SoEvent) bool {
	return (event.TcpFlags&0x04) != 0 && event.IPProto == core.ProtocolTCP
}

func (r *RSTColorRule) GetColor() Color { return ColorRed }

func (r *RSTColorRule) GetText(event *core.SoEvent) string {
	return "RST"
}

// TTLColorRule TTL高值黄色规则
type TTLColorRule struct{}

func (r *TTLColorRule) Name() string { return "TTL" }

func (r *TTLColorRule) ShouldApply(event *core.SoEvent) bool {
	return event.TTL > 100
}

func (r *TTLColorRule) GetColor() Color { return ColorYellow }

func (r *TTLColorRule) GetText(event *core.SoEvent) string {
	return ""
}

// MACVendorColorRule MAC厂商名称黄色规则
type MACVendorColorRule struct{}

func (r *MACVendorColorRule) Name() string { return "MAC_VENDOR" }

func (r *MACVendorColorRule) ShouldApply(event *core.SoEvent) bool {
	// 检查MAC地址是否包含厂商名称
	resolver, err := core.GetMacResolver()
	if err != nil {
		return false
	}
	macStr := resolver.ResolveMacAddress(event.SrcMac)
	return strings.Contains(macStr, "(") && strings.Contains(macStr, ")")
}

func (r *MACVendorColorRule) GetColor() Color { return ColorYellow }

func (r *MACVendorColorRule) GetText(event *core.SoEvent) string {
	return ""
}
