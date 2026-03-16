package diagnose

import (
	"fmt"
	"strings"
	"time"
)

const maxKeySamples = 8

// Summary 表示一次抓包会话的本地摘要。
type Summary struct {
	CommandLine      string
	ExitReason       string
	StartTime        time.Time
	EndTime          time.Time
	CaptureSizeBytes int64
	TotalLines       int
	ProtocolCounts   map[string]int
	DropCount        int
	RetransmitCount  int
	RSTCount         int
	KeySamples       []string
}

// BuildSummary 从抓包原文生成本地摘要。
func BuildSummary(capture string, captureSize int64, commandLine string, startTime, endTime time.Time, exitReason string) Summary {
	summary := Summary{
		CommandLine:      commandLine,
		ExitReason:       exitReason,
		StartTime:        startTime,
		EndTime:          endTime,
		CaptureSizeBytes: captureSize,
		ProtocolCounts: map[string]int{
			"TCP":  0,
			"UDP":  0,
			"ICMP": 0,
		},
	}

	lines := strings.Split(strings.ReplaceAll(capture, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Time") || strings.HasPrefix(line, "----") {
			continue
		}

		summary.TotalLines++
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			proto := strings.ToUpper(fields[3])
			if _, ok := summary.ProtocolCounts[proto]; ok {
				summary.ProtocolCounts[proto]++
			}
		}

		isKeySample := false
		if strings.Contains(line, ":DROP") {
			summary.DropCount++
			isKeySample = true
		}
		if strings.Contains(line, "[TCP Retransmission]") {
			summary.RetransmitCount++
			isKeySample = true
		}
		if strings.Contains(line, "RST") {
			summary.RSTCount++
			isKeySample = true
		}

		if isKeySample && len(summary.KeySamples) < maxKeySamples {
			summary.KeySamples = append(summary.KeySamples, line)
		}
	}

	return summary
}

// FormatForPrompt 将摘要格式化为适合提交给 AI 的说明文本。
func (s Summary) FormatForPrompt() string {
	var b strings.Builder
	fmt.Fprintf(&b, "- 运行命令: %s\n", s.CommandLine)
	fmt.Fprintf(&b, "- 退出原因: %s\n", s.ExitReason)
	fmt.Fprintf(&b, "- 抓包开始时间: %s\n", formatTime(s.StartTime))
	fmt.Fprintf(&b, "- 抓包结束时间: %s\n", formatTime(s.EndTime))
	fmt.Fprintf(&b, "- 抓包文本大小: %d bytes\n", s.CaptureSizeBytes)
	fmt.Fprintf(&b, "- 抓包有效行数: %d\n", s.TotalLines)
	fmt.Fprintf(&b, "- 协议分布: TCP=%d, UDP=%d, ICMP=%d\n", s.ProtocolCounts["TCP"], s.ProtocolCounts["UDP"], s.ProtocolCounts["ICMP"])
	fmt.Fprintf(&b, "- DROP 次数: %d\n", s.DropCount)
	fmt.Fprintf(&b, "- TCP 重传次数: %d\n", s.RetransmitCount)
	fmt.Fprintf(&b, "- RST 次数: %d\n", s.RSTCount)

	if len(s.KeySamples) > 0 {
		b.WriteString("- 关键异常样本:\n")
		for _, sample := range s.KeySamples {
			fmt.Fprintf(&b, "  - %s\n", sample)
		}
	}

	return b.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339)
}
