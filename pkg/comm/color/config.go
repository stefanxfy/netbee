package color

// Config 颜色配置
type Config struct {
	Enabled    bool
	ForceColor bool
	NoColor    bool
	ColorDepth int
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	detector := &TerminalDetector{}
	return &Config{
		Enabled:    detector.SupportsColor(),
		ForceColor: false,
		NoColor:    false,
		ColorDepth: detector.GetColorDepth(),
	}
}

// NewConfig 创建配置
func NewConfig(noColor bool, forceColor bool) *Config {
	config := DefaultConfig()

	if noColor {
		config.Enabled = false
		config.NoColor = true
	} else if forceColor {
		config.Enabled = true
		config.ForceColor = true
	}

	return config
}
