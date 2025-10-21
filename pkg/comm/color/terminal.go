package color

import (
	"os"
	"strings"
)

// TerminalDetector 终端检测器
type TerminalDetector struct{}

// IsTerminal 检查是否在终端中运行
func (td *TerminalDetector) IsTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// SupportsColor 检查终端是否支持颜色
func (td *TerminalDetector) SupportsColor() bool {
	if !td.IsTerminal() {
		return false
	}

	// 检查TERM环境变量
	term := os.Getenv("TERM")
	if term == "" {
		return false
	}

	// 检查NO_COLOR环境变量
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// 检查COLORTERM环境变量
	colorterm := os.Getenv("COLORTERM")
	if colorterm == "truecolor" || colorterm == "24bit" {
		return true
	}

	// 检查TERM是否支持颜色
	colorTerms := []string{"xterm", "xterm-256color", "screen", "tmux", "rxvt"}
	for _, ct := range colorTerms {
		if strings.Contains(term, ct) {
			return true
		}
	}

	return false
}

// GetColorDepth 获取终端颜色深度
func (td *TerminalDetector) GetColorDepth() int {
	if !td.SupportsColor() {
		return 0
	}

	// 检查COLORTERM
	colorterm := os.Getenv("COLORTERM")
	if colorterm == "truecolor" || colorterm == "24bit" {
		return 24
	}

	// 检查TERM
	term := os.Getenv("TERM")
	if strings.Contains(term, "256") {
		return 8
	}

	return 4
}
