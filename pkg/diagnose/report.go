package diagnose

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportInput 是诊断报告生成所需的数据。
type ReportInput struct {
	Summary       Summary
	Result        *AnalyzeResult
	ReportError   error
	RawResponse   []byte
	RawSave       bool
	RequestedPath string
}

// ReportOutput 表示生成后的文件路径。
type ReportOutput struct {
	ReportPath         string
	RawResponsePath    string
	CaptureDownloadURL string
}

// WriteReport 将 AI 诊断结果落盘为 Markdown 或 TXT 文件。
func WriteReport(input ReportInput) (*ReportOutput, error) {
	reportPath := input.RequestedPath
	if strings.TrimSpace(reportPath) == "" {
		reportPath = fmt.Sprintf("diagnosis-%s.md", time.Now().Format("20060102-150405"))
	}
	if filepath.Ext(reportPath) == "" {
		reportPath += ".md"
	}

	content, err := buildReportContent(reportPath, input)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(reportPath, []byte(content), 0o644); err != nil {
		return nil, err
	}

	output := &ReportOutput{
		ReportPath: reportPath,
	}
	if input.Result != nil {
		output.CaptureDownloadURL = strings.TrimSpace(input.Result.CaptureDownloadURL)
	}
	rawContent := input.RawResponse
	if input.Result != nil && len(input.Result.RawResponse) > 0 {
		rawContent = input.Result.RawResponse
	}
	if input.RawSave && len(rawContent) > 0 {
		rawPath := strings.TrimSuffix(reportPath, filepath.Ext(reportPath)) + ".raw.json"
		var pretty any
		if json.Unmarshal(rawContent, &pretty) == nil {
			if indented, err := json.MarshalIndent(pretty, "", "  "); err == nil {
				rawContent = indented
			}
		}
		if err := os.WriteFile(rawPath, rawContent, 0o644); err != nil {
			return nil, err
		}
		output.RawResponsePath = rawPath
	}

	return output, nil
}

func buildReportContent(reportPath string, input ReportInput) (string, error) {
	switch strings.ToLower(filepath.Ext(reportPath)) {
	case ".txt":
		return buildTextReport(input), nil
	default:
		return buildMarkdownReport(input), nil
	}
}

func buildMarkdownReport(input ReportInput) string {
	var b strings.Builder
	b.WriteString("# NetBee AI 诊断报告\n\n")
	b.WriteString("## 基本信息\n")
	b.WriteString(fmt.Sprintf("- 运行命令: `%s`\n", input.Summary.CommandLine))
	b.WriteString(fmt.Sprintf("- 退出原因: %s\n", input.Summary.ExitReason))
	b.WriteString(fmt.Sprintf("- 抓包开始时间: %s\n", formatTime(input.Summary.StartTime)))
	b.WriteString(fmt.Sprintf("- 抓包结束时间: %s\n", formatTime(input.Summary.EndTime)))
	b.WriteString(fmt.Sprintf("- 抓包文本大小: %d bytes\n", input.Summary.CaptureSizeBytes))
	b.WriteString(fmt.Sprintf("- 抓包有效行数: %d\n", input.Summary.TotalLines))
	b.WriteString(fmt.Sprintf("- 协议分布: TCP=%d, UDP=%d, ICMP=%d\n", input.Summary.ProtocolCounts["TCP"], input.Summary.ProtocolCounts["UDP"], input.Summary.ProtocolCounts["ICMP"]))
	b.WriteString(fmt.Sprintf("- DROP 次数: %d\n", input.Summary.DropCount))
	b.WriteString(fmt.Sprintf("- TCP 重传次数: %d\n", input.Summary.RetransmitCount))
	b.WriteString(fmt.Sprintf("- RST 次数: %d\n", input.Summary.RSTCount))
	if input.Result != nil && strings.TrimSpace(input.Result.CaptureDownloadURL) != "" {
		b.WriteString(fmt.Sprintf("- 抓包文件下载链接: %s\n", input.Result.CaptureDownloadURL))
	}

	if len(input.Summary.KeySamples) > 0 {
		b.WriteString("\n## 关键异常样本\n")
		for _, sample := range input.Summary.KeySamples {
			b.WriteString(fmt.Sprintf("- `%s`\n", sample))
		}
	}

	b.WriteString("\n## AI 诊断结果\n")
	if input.ReportError != nil {
		b.WriteString(fmt.Sprintf("AI 诊断失败：%v\n", input.ReportError))
	} else if input.Result != nil {
		b.WriteString(input.Result.Response.Answer)
		if !strings.HasSuffix(input.Result.Response.Answer, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("AI 未返回结果。\n")
	}

	if input.Result != nil {
		b.WriteString("\n## AI 调用元数据\n")
		b.WriteString(fmt.Sprintf("- `task_id`: `%s`\n", input.Result.Response.TaskID))
		b.WriteString(fmt.Sprintf("- `message_id`: `%s`\n", input.Result.Response.MessageID))
		b.WriteString(fmt.Sprintf("- `conversation_id`: `%s`\n", input.Result.Response.ConversationID))
		b.WriteString(fmt.Sprintf("- `content_type`: `%s`\n", input.Result.ContentType))
		b.WriteString(fmt.Sprintf("- `used_file_upload`: `%t`\n", input.Result.UsedFileUpload))
		b.WriteString(fmt.Sprintf("- `used_inline_fallback`: `%t`\n", input.Result.UsedInlineFallback))
		b.WriteString(fmt.Sprintf("- `inline_truncated`: `%t`\n", input.Result.InlineTruncated))
		if input.Result.FileUploadError != "" {
			b.WriteString(fmt.Sprintf("- `file_upload_error`: `%s`\n", input.Result.FileUploadError))
		}
		b.WriteString(fmt.Sprintf("- `total_tokens`: `%d`\n", input.Result.Response.Metadata.Usage.TotalTokens))
		b.WriteString(fmt.Sprintf("- `latency`: `%.3fs`\n", input.Result.Response.Metadata.Usage.Latency))
		b.WriteString(fmt.Sprintf("- `total_price`: `%s %s`\n", input.Result.Response.Metadata.Usage.TotalPrice, input.Result.Response.Metadata.Usage.Currency))
	}

	return b.String()
}

func buildTextReport(input ReportInput) string {
	var b strings.Builder
	b.WriteString("NetBee AI 诊断报告\n")
	b.WriteString(strings.Repeat("=", 24))
	b.WriteString("\n\n")
	b.WriteString("基本信息\n")
	b.WriteString(fmt.Sprintf("- 运行命令: %s\n", input.Summary.CommandLine))
	b.WriteString(fmt.Sprintf("- 退出原因: %s\n", input.Summary.ExitReason))
	b.WriteString(fmt.Sprintf("- 抓包开始时间: %s\n", formatTime(input.Summary.StartTime)))
	b.WriteString(fmt.Sprintf("- 抓包结束时间: %s\n", formatTime(input.Summary.EndTime)))
	b.WriteString(fmt.Sprintf("- 抓包文本大小: %d bytes\n", input.Summary.CaptureSizeBytes))
	b.WriteString(fmt.Sprintf("- 抓包有效行数: %d\n", input.Summary.TotalLines))
	b.WriteString(fmt.Sprintf("- 协议分布: TCP=%d, UDP=%d, ICMP=%d\n", input.Summary.ProtocolCounts["TCP"], input.Summary.ProtocolCounts["UDP"], input.Summary.ProtocolCounts["ICMP"]))
	b.WriteString(fmt.Sprintf("- DROP 次数: %d\n", input.Summary.DropCount))
	b.WriteString(fmt.Sprintf("- TCP 重传次数: %d\n", input.Summary.RetransmitCount))
	b.WriteString(fmt.Sprintf("- RST 次数: %d\n", input.Summary.RSTCount))
	if input.Result != nil && strings.TrimSpace(input.Result.CaptureDownloadURL) != "" {
		b.WriteString(fmt.Sprintf("- 抓包文件下载链接: %s\n", input.Result.CaptureDownloadURL))
	}

	if len(input.Summary.KeySamples) > 0 {
		b.WriteString("\n关键异常样本\n")
		for _, sample := range input.Summary.KeySamples {
			b.WriteString(fmt.Sprintf("- %s\n", sample))
		}
	}

	b.WriteString("\nAI 诊断结果\n")
	if input.ReportError != nil {
		b.WriteString(fmt.Sprintf("AI 诊断失败：%v\n", input.ReportError))
	} else if input.Result != nil {
		b.WriteString(input.Result.Response.Answer)
		if !strings.HasSuffix(input.Result.Response.Answer, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("AI 未返回结果。\n")
	}

	if input.Result != nil {
		b.WriteString("\nAI 调用元数据\n")
		b.WriteString(fmt.Sprintf("- task_id: %s\n", input.Result.Response.TaskID))
		b.WriteString(fmt.Sprintf("- message_id: %s\n", input.Result.Response.MessageID))
		b.WriteString(fmt.Sprintf("- conversation_id: %s\n", input.Result.Response.ConversationID))
		b.WriteString(fmt.Sprintf("- content_type: %s\n", input.Result.ContentType))
		b.WriteString(fmt.Sprintf("- used_file_upload: %t\n", input.Result.UsedFileUpload))
		b.WriteString(fmt.Sprintf("- used_inline_fallback: %t\n", input.Result.UsedInlineFallback))
		b.WriteString(fmt.Sprintf("- inline_truncated: %t\n", input.Result.InlineTruncated))
		if input.Result.FileUploadError != "" {
			b.WriteString(fmt.Sprintf("- file_upload_error: %s\n", input.Result.FileUploadError))
		}
		b.WriteString(fmt.Sprintf("- total_tokens: %d\n", input.Result.Response.Metadata.Usage.TotalTokens))
		b.WriteString(fmt.Sprintf("- latency: %.3fs\n", input.Result.Response.Metadata.Usage.Latency))
		b.WriteString(fmt.Sprintf("- total_price: %s %s\n", input.Result.Response.Metadata.Usage.TotalPrice, input.Result.Response.Metadata.Usage.Currency))
	}

	return b.String()
}
