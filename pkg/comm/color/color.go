package color

// ANSI颜色代码常量
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Gray    = "\033[90m"
)

// 颜色类型
type Color string

// 预定义颜色
const (
	ColorReset   Color = Reset
	ColorRed     Color = Red
	ColorGreen   Color = Green
	ColorYellow  Color = Yellow
	ColorBlue    Color = Blue
	ColorMagenta Color = Magenta
	ColorCyan    Color = Cyan
	ColorWhite   Color = White
	ColorGray    Color = Gray
)

// Apply 应用颜色到文本
func (c Color) Apply(text string) string {
	return string(c) + text + Reset
}

// Wrap 包装文本（与Apply相同）
func (c Color) Wrap(text string) string {
	return string(c) + text + Reset
}

// IsEmpty 检查颜色是否为空
func (c Color) IsEmpty() bool {
	return string(c) == ""
}
