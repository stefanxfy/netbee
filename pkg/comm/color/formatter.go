package color

import (
	"fmt"
	"netbee/pkg/core"
	"strings"
)

// Formatter 格式化器接口
type Formatter interface {
	FormatEvent(event *core.SoEvent, symbolResolver *core.SymbolResolver) string
	FormatTTL(event *core.SoEvent) string
	FormatMAC(event *core.SoEvent) string
	FormatInfo(event *core.SoEvent, symbolResolver *core.SymbolResolver) string
}

// ColorFormatter 颜色格式化器
type ColorFormatter struct {
	enabled bool
	rules   []ColorRule
}

// NewColorFormatter 创建颜色格式化器
func NewColorFormatter(enabled bool) *ColorFormatter {
	return &ColorFormatter{
		enabled: enabled,
		rules: []ColorRule{
			&RSTColorRule{},
			&TTLColorRule{},
			&MACVendorColorRule{},
		},
	}
}

// FormatTTL 格式化TTL字段
func (f *ColorFormatter) FormatTTL(event *core.SoEvent) string {
	if !f.enabled {
		return fmt.Sprintf("%d", event.TTL)
	}

	for _, rule := range f.rules {
		if rule.Name() == "TTL" && rule.ShouldApply(event) {
			return rule.GetColor().Apply(fmt.Sprintf("%d", event.TTL))
		}
	}

	return fmt.Sprintf("%d", event.TTL)
}

// FormatMAC 格式化MAC地址
func (f *ColorFormatter) FormatMAC(event *core.SoEvent) string {
	resolver, err := core.GetMacResolver()
	if err != nil {
		return core.MacToString(event.SrcMac)
	}

	macStr := resolver.ResolveMacAddress(event.SrcMac)

	if !f.enabled {
		return macStr
	}

	// 检查是否有厂商名称需要着色
	for _, rule := range f.rules {
		if rule.Name() == "MAC_VENDOR" && rule.ShouldApply(event) {
			return f.applyMACVendorColor(macStr)
		}
	}

	return macStr
}

// FormatInfo 格式化Info字段
func (f *ColorFormatter) FormatInfo(event *core.SoEvent, symbolResolver *core.SymbolResolver) string {
	infoStr := event.FormatEventInfo(symbolResolver)

	if !f.enabled {
		return infoStr
	}

	// 检查RST标志
	for _, rule := range f.rules {
		if rule.Name() == "RST" && rule.ShouldApply(event) {
			return f.applyRSTColor(event, symbolResolver)
		}
	}

	return infoStr
}

// applyMACVendorColor 应用MAC厂商名称颜色
func (f *ColorFormatter) applyMACVendorColor(macStr string) string {
	if strings.Contains(macStr, "(") && strings.Contains(macStr, ")") {
		openParen := strings.Index(macStr, "(")
		closeParen := strings.Index(macStr, ")")

		if openParen > 0 && closeParen > openParen {
			macPart := macStr[:openParen]
			vendorPart := macStr[openParen : closeParen+1]
			return macPart + ColorYellow.Wrap(vendorPart)
		}
	}
	return macStr
}

// applyRSTColor 应用RST标志颜色
func (f *ColorFormatter) applyRSTColor(event *core.SoEvent, symbolResolver *core.SymbolResolver) string {
	// 重新构建带颜色的flags字符串
	flagParts := make([]string, 0)
	flags := event.TcpFlags

	if flags&0x01 != 0 { // FIN
		flagParts = append(flagParts, "FIN")
	}
	if flags&0x02 != 0 { // SYN
		flagParts = append(flagParts, "SYN")
	}
	if flags&0x04 != 0 { // RST - 用红色显示
		flagParts = append(flagParts, ColorRed.Wrap("RST"))
	}
	if flags&0x08 != 0 { // PSH
		flagParts = append(flagParts, "PSH")
	}
	if flags&0x10 != 0 { // ACK
		flagParts = append(flagParts, "ACK")
	}
	if flags&0x20 != 0 { // URG
		flagParts = append(flagParts, "URG")
	}
	if flags&0x40 != 0 { // ECE
		flagParts = append(flagParts, "ECE")
	}
	if flags&0x80 != 0 { // CWR
		flagParts = append(flagParts, "CWR")
	}

	var coloredFlags string
	if len(flagParts) == 0 {
		coloredFlags = "NONE"
	} else {
		coloredFlags = strings.Join(flagParts, ",")
	}

	// 重新构建Info字符串
	ifaceName := core.IfIndexToName(event.IfIndex)
	funcName := event.GetFunctionName()

	stackInfo := core.FormatStackTrace(event.StackTrace, event.StackDepth, symbolResolver)

	var nfInfo string
	if event.NFHook != 0 || event.Verdict != 0 {
		nfInfo = " NF:" + core.FormatNFInfo(event.NFHook, event.Verdict)
	}

	return fmt.Sprintf("%d->%d %s Seq:%d Ack:%d %s [%s] PID:%d%s%s",
		event.SrcPort, event.DstPort, coloredFlags, event.TcpSeq, event.TcpAck,
		ifaceName, funcName, event.Pid, stackInfo, nfInfo)
}
