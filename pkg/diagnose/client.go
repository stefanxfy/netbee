package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

const (
	defaultAPIURL         = "https://dify.cvte.com/v1/chat-messages"
	defaultUploadURL      = "https://eg-cloud.seewo.com/eg/v1/enm/uploadFileTmp"
	maxInlineCaptureBytes = 64 * 1024
)

// Options 控制 AI 诊断行为。
type Options struct {
	Enabled     bool
	APIURL      string
	APIKey      string
	User        string
	OutputPath  string
	Timeout     time.Duration
	SaveRaw     bool
	MemoryLimit int64
}

// Client 负责调用云端 AI 接口。
type Client struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
}

// APIError 表示云端接口返回的错误。
type APIError struct {
	StatusCode int
	Code       string `json:"code"`
	Message    string `json:"message"`
	Status     int    `json:"status"`
	Body       string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return fmt.Sprintf("AI 接口错误(%d/%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("AI 接口错误(%d): %s", e.StatusCode, e.Message)
}

// Response 表示阻塞式 Dify 响应。
type Response struct {
	Event          string   `json:"event"`
	TaskID         string   `json:"task_id"`
	ID             string   `json:"id"`
	MessageID      string   `json:"message_id"`
	ConversationID string   `json:"conversation_id"`
	Mode           string   `json:"mode"`
	Answer         string   `json:"answer"`
	Metadata       Metadata `json:"metadata"`
	CreatedAt      int64    `json:"created_at"`
}

// Metadata 保存 token 和时延信息。
type Metadata struct {
	Usage Usage `json:"usage"`
}

// Usage 为 Dify 阻塞响应中的 usage 字段。
type Usage struct {
	PromptTokens        int     `json:"prompt_tokens"`
	CompletionTokens    int     `json:"completion_tokens"`
	TotalTokens         int     `json:"total_tokens"`
	TotalPrice          string  `json:"total_price"`
	Currency            string  `json:"currency"`
	Latency             float64 `json:"latency"`
	PromptPrice         string  `json:"prompt_price"`
	CompletionPrice     string  `json:"completion_price"`
	PromptUnitPrice     string  `json:"prompt_unit_price"`
	CompletionUnitPrice string  `json:"completion_unit_price"`
}

// AnalyzeResult 保存一次调用的结果与调试信息。
type AnalyzeResult struct {
	Response           Response
	RawResponse        []byte
	ContentType        string
	PromptUsed         string
	CaptureDownloadURL string
	UsedFileUpload     bool
	UsedInlineFallback bool
	InlineTruncated    bool
	FileUploadError    string
}

type analyzePayload struct {
	Inputs       map[string]any    `json:"inputs"`
	Query        string            `json:"query"`
	ResponseMode string            `json:"response_mode"`
	User         string            `json:"user"`
	Files        []analyzeFileItem `json:"files,omitempty"`
}

type analyzeFileItem struct {
	Type           string `json:"type"`
	TransferMethod string `json:"transfer_method"`
	URL            string `json:"url,omitempty"`
}

type uploadTmpResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		DownloadURL string `json:"downloadUrl"`
	} `json:"data"`
}

// NewClient 创建 AI 客户端。
func NewClient(opts Options) *Client {
	apiURL := strings.TrimSpace(opts.APIURL)
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	return &Client{
		apiURL: apiURL,
		apiKey: strings.TrimSpace(opts.APIKey),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Analyze 执行一次 AI 诊断。
func (c *Client) Analyze(ctx context.Context, opts Options, summary Summary, capture []byte) (*AnalyzeResult, error) {
	if strings.TrimSpace(c.apiKey) == "" {
		return nil, fmt.Errorf("未配置 AI API Key")
	}

	basePrompt := BuildPrompt(summary)
	result, err := c.analyzeWithFile(ctx, opts.User, basePrompt, capture)
	if err == nil {
		result.PromptUsed = basePrompt
		return result, nil
	}

	apiErr, ok := err.(*APIError)
	if !ok || !shouldFallbackInline(apiErr) {
		return result, err
	}

	inlinePrompt, inlineTruncated := buildInlinePrompt(basePrompt, capture)
	fallbackResult, fallbackErr := c.analyzeInline(ctx, opts.User, inlinePrompt)
	if fallbackErr != nil {
		return nil, fallbackErr
	}
	fallbackResult.PromptUsed = inlinePrompt
	fallbackResult.UsedInlineFallback = true
	fallbackResult.FileUploadError = apiErr.Message
	fallbackResult.InlineTruncated = inlineTruncated
	return fallbackResult, nil
}

func (c *Client) analyzeWithFile(ctx context.Context, user, prompt string, capture []byte) (*AnalyzeResult, error) {
	downloadURL, err := c.uploadCaptureFile(ctx, capture)
	if err != nil {
		return nil, err
	}

	payload := analyzePayload{
		Inputs:       map[string]any{},
		Query:        prompt,
		ResponseMode: "blocking",
		User:         user,
		Files: []analyzeFileItem{{
			Type:           "document",
			TransferMethod: "remote_url",
			URL:            downloadURL,
		}},
	}

	result, err := c.send(ctx, payload)
	if err != nil {
		return &AnalyzeResult{
			PromptUsed:         prompt,
			CaptureDownloadURL: downloadURL,
			UsedFileUpload:     true,
		}, err
	}
	result.CaptureDownloadURL = downloadURL
	result.UsedFileUpload = true
	return result, nil
}

func (c *Client) analyzeInline(ctx context.Context, user, prompt string) (*AnalyzeResult, error) {
	payload := analyzePayload{
		Inputs:       map[string]any{},
		Query:        prompt,
		ResponseMode: "blocking",
		User:         user,
	}
	return c.send(ctx, payload)
}

func (c *Client) send(ctx context.Context, payload analyzePayload) (*AnalyzeResult, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
		_ = json.Unmarshal(respBody, apiErr)
		if apiErr.Message == "" {
			apiErr.Message = string(respBody)
		}
		return nil, apiErr
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       "unexpected_streaming_response",
			Message:    "收到 text/event-stream，当前实现仅支持 blocking JSON 响应",
			Body:       string(respBody),
		}
	}

	var parsed Response
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("解析 AI 响应失败: %w", err)
	}

	return &AnalyzeResult{
		Response:    parsed,
		RawResponse: respBody,
		ContentType: contentType,
	}, nil
}

func (c *Client) uploadCaptureFile(ctx context.Context, capture []byte) (string, error) {
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="netbee-capture.txt"`)
	header.Set("Content-Type", "text/plain")

	part, err := writer.CreatePart(header)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(capture); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultUploadURL, &requestBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", &APIError{
			StatusCode: resp.StatusCode,
			Code:       "upload_http_status_error",
			Message:    fmt.Sprintf("上传抓包文件失败，HTTP 状态码: %d", resp.StatusCode),
			Body:       string(respBody),
		}
	}

	var parsed uploadTmpResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("解析临时文件上传响应失败: %w", err)
	}

	if parsed.Code != 0 {
		return "", &APIError{
			StatusCode: resp.StatusCode,
			Code:       "upload_tmp_code_error",
			Message:    fmt.Sprintf("上传抓包文件失败，code=%d, message=%s", parsed.Code, parsed.Message),
			Body:       string(respBody),
		}
	}

	downloadURL := strings.TrimSpace(parsed.Data.DownloadURL)
	if downloadURL == "" {
		return "", &APIError{
			StatusCode: resp.StatusCode,
			Code:       "upload_tmp_missing_download_url",
			Message:    "上传成功但未返回 downloadUrl",
			Body:       string(respBody),
		}
	}

	return downloadURL, nil
}

func BuildPrompt(summary Summary) string {
	return strings.TrimSpace(fmt.Sprintf(`你是一名资深网络排障工程师，请根据 netbee 抓包结果分析问题。

你必须严格按下面的 Markdown 模板输出，标题名称、标题层级、分隔线都不要改，不能缺少任何章节，不能输出模板之外的额外前言、后记或客套话。

固定格式要求：
1. 必须包含且仅按以下顺序输出这些一级/二级标题：
   - ## 0. 整个网络链路过程：问题出在哪个环节
   - ## 1. 现象总结
   - ## 2. 最可能的根因（按概率排序）
   - ## 3. 关键证据
   - ## 4. 建议的排查步骤
   - ## 5. 风险与影响判断
   - # 结论
   - ## 综合判断
2. 在 # 结论 之前必须单独输出一行 ---
3. 在 ## 综合判断 章节末尾必须再单独输出一行 ---
4. # 结论 下必须先写 ## 综合判断
5. ## 综合判断 下必须包含两个固定三级标题：
   - ### 已知异常
   - ### 最可能根因
6. ### 最可能根因 下必须输出编号列表 1. 2. 3. 4.
7. 不要把“综合判断”写成“综合结论”或其他近义词，必须严格使用 ## 综合判断
8. 不要使用代码块包裹全文

请直接按下面模板产出内容：

## 0. 整个网络链路过程：问题出在哪个环节
[正文]

## 1. 现象总结
[正文]

## 2. 最可能的根因（按概率排序）
[正文]

## 3. 关键证据
[正文]

## 4. 建议的排查步骤
[正文]

## 5. 风险与影响判断
[正文]

---

# 结论

## 综合判断
[先给 1-2 句总判断]

### 已知异常
- [异常1]
- [异常2]
- [异常3]

### 最可能根因
1. [根因1]
2. [根因2]
3. [根因3]
4. [根因4]

---

以下是本次抓包的本地摘要：
%s`, summary.FormatForPrompt()))
}

func buildInlinePrompt(basePrompt string, capture []byte) (string, bool) {
	inline := capture
	truncated := false
	if len(inline) > maxInlineCaptureBytes {
		inline = inline[:maxInlineCaptureBytes]
		truncated = true
	}

	var b strings.Builder
	b.WriteString(basePrompt)
	b.WriteString("\n\n以下是抓包原文：\n```text\n")
	b.Write(inline)
	if len(inline) == 0 || inline[len(inline)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString("```\n")
	if truncated {
		b.WriteString("\n注意：由于接口文件协议回退为内联文本，本次只附带了抓包原文前 64KB。\n")
	}

	return b.String(), truncated
}

func shouldFallbackInline(err *APIError) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Message)
	return (err.StatusCode == http.StatusBadRequest && strings.Contains(message, "invalid file")) ||
		strings.Contains(strings.ToLower(err.Code), "upload_")
}
