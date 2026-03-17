package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	neturl "net/url"
	"strings"
	"time"
)

const (
	defaultAPIURL         = "https://dify.cvte.com/v1/chat-messages"
	defaultMessagesURL    = "https://dify.cvte.com/v1/messages"
	defaultUploadURL      = "https://eg-cloud.seewo.com/eg/v1/enm/uploadFileTmp"
	maxInlineCaptureBytes = 64 * 1024
	maxChatAttempts       = 3
)

// Options 控制 AI 诊断行为。
type Options struct {
	Enabled          bool
	APIURL           string
	APIKey           string
	User             string
	OutputPath       string
	Timeout          time.Duration
	SaveRaw          bool
	KeepConversation bool
	ConversationID   string
	MemoryLimit      int64
}

// Client 负责调用云端 AI 接口。
type Client struct {
	apiURL      string
	messagesURL string
	apiKey      string
	httpClient  *http.Client
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
	Inputs         map[string]any    `json:"inputs"`
	Query          string            `json:"query"`
	ResponseMode   string            `json:"response_mode"`
	User           string            `json:"user"`
	ConversationID string            `json:"conversation_id,omitempty"`
	Files          []analyzeFileItem `json:"files,omitempty"`
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
		apiURL:      apiURL,
		messagesURL: buildMessagesURL(apiURL),
		apiKey:      strings.TrimSpace(opts.APIKey),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ValidateConversation 通过 /messages 预检 conversation_id 是否可用。
func (c *Client) ValidateConversation(ctx context.Context, user, conversationID string) (bool, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return false, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.messagesURL, nil)
	if err != nil {
		return false, err
	}

	query := req.URL.Query()
	query.Set("conversation_id", conversationID)
	query.Set("user", strings.TrimSpace(user))
	query.Set("limit", "1")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return true, nil
	}

	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Body:       string(respBody),
	}
	_ = json.Unmarshal(respBody, apiErr)
	if apiErr.Message == "" {
		apiErr.Message = string(respBody)
	}
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, apiErr
}

// Analyze 执行一次 AI 诊断。
func (c *Client) Analyze(ctx context.Context, opts Options, summary Summary, capture []byte) (*AnalyzeResult, error) {
	if strings.TrimSpace(c.apiKey) == "" {
		return nil, fmt.Errorf("未配置 AI API Key")
	}

	hasConversation := strings.TrimSpace(opts.ConversationID) != ""
	basePrompt := BuildPrompt(summary, hasConversation)
	result, err := c.analyzeWithFile(ctx, opts, basePrompt, capture)
	if err == nil {
		result.PromptUsed = basePrompt
		return result, nil
	}

	if hasConversation {
		apiErr, ok := err.(*APIError)
		if ok && shouldDropConversation(apiErr) {
			log.Printf("当前 conversation_id 无效或已失效，按首次诊断重试: %v", err)
			opts.ConversationID = ""
			basePrompt = BuildPrompt(summary, false)
			retryResult, retryErr := c.analyzeWithFile(ctx, opts, basePrompt, capture)
			if retryErr == nil {
				retryResult.PromptUsed = basePrompt
				return retryResult, nil
			}
			err = retryErr
			result = retryResult
		}
	}

	apiErr, ok := err.(*APIError)
	if !ok || !shouldFallbackInline(apiErr) {
		return result, err
	}

	inlinePrompt, inlineTruncated := buildInlinePrompt(basePrompt, capture)
	fallbackResult, fallbackErr := c.analyzeInline(ctx, opts, inlinePrompt)
	if fallbackErr != nil {
		return nil, fallbackErr
	}
	fallbackResult.PromptUsed = inlinePrompt
	if result != nil {
		fallbackResult.CaptureDownloadURL = result.CaptureDownloadURL
	}
	fallbackResult.UsedInlineFallback = true
	fallbackResult.FileUploadError = apiErr.Message
	fallbackResult.InlineTruncated = inlineTruncated
	return fallbackResult, nil
}

func (c *Client) analyzeWithFile(ctx context.Context, opts Options, prompt string, capture []byte) (*AnalyzeResult, error) {
	downloadURL, err := c.uploadCaptureFile(ctx, capture)
	if err != nil {
		return nil, err
	}

	payload := analyzePayload{
		Inputs:         map[string]any{},
		Query:          prompt,
		ResponseMode:   "blocking",
		User:           opts.User,
		ConversationID: strings.TrimSpace(opts.ConversationID),
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

func (c *Client) analyzeInline(ctx context.Context, opts Options, prompt string) (*AnalyzeResult, error) {
	payload := analyzePayload{
		Inputs:         map[string]any{},
		Query:          prompt,
		ResponseMode:   "blocking",
		User:           opts.User,
		ConversationID: strings.TrimSpace(opts.ConversationID),
	}
	return c.send(ctx, payload)
}

func (c *Client) send(ctx context.Context, payload analyzePayload) (*AnalyzeResult, error) {
	var lastErr error
	for attempt := 1; attempt <= maxChatAttempts; attempt++ {
		result, err := c.sendOnce(ctx, payload)
		if err == nil {
			if attempt > 1 {
				log.Printf("AI 问答请求在第 %d/%d 次尝试后成功", attempt, maxChatAttempts)
			}
			return result, nil
		}

		lastErr = err
		retriable := attempt < maxChatAttempts && ctx.Err() == nil && shouldRetryChatRequest(err)
		if retriable {
			delay := time.Duration(attempt) * time.Second
			log.Printf("AI 问答请求第 %d/%d 次失败: %v；%s 后重试", attempt, maxChatAttempts, err, delay)
			if waitErr := waitRetry(ctx, delay); waitErr != nil {
				lastErr = waitErr
				break
			}
			continue
		}

		if attempt == maxChatAttempts && shouldRetryChatRequest(err) {
			log.Printf("AI 问答请求连续 %d 次失败，停止重试: %v", maxChatAttempts, err)
		} else {
			log.Printf("AI 问答请求失败，不再重试: %v", err)
		}
		return nil, err
	}

	if lastErr != nil {
		log.Printf("AI 问答请求最终失败: %v", lastErr)
	}
	return nil, lastErr
}

func (c *Client) sendOnce(ctx context.Context, payload analyzePayload) (*AnalyzeResult, error) {
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

func shouldRetryChatRequest(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}

	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusTooManyRequests ||
			apiErr.StatusCode == http.StatusRequestTimeout ||
			apiErr.StatusCode >= http.StatusInternalServerError {
			return true
		}
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	return false
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func buildMessagesURL(apiURL string) string {
	if strings.TrimSpace(apiURL) == "" {
		return defaultMessagesURL
	}

	parsed, err := neturl.Parse(apiURL)
	if err != nil {
		return defaultMessagesURL
	}

	path := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(path, "/chat-messages") {
		path = strings.TrimSuffix(path, "/chat-messages")
	}
	if path == "" {
		path = "/messages"
	} else {
		path += "/messages"
	}
	parsed.Path = path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func shouldDropConversation(err *APIError) bool {
	if err == nil {
		return false
	}
	if err.StatusCode == http.StatusNotFound {
		return true
	}

	message := strings.ToLower(strings.TrimSpace(err.Message))
	code := strings.ToLower(strings.TrimSpace(err.Code))
	body := strings.ToLower(strings.TrimSpace(err.Body))

	if strings.Contains(code, "conversation") {
		return true
	}
	if strings.Contains(message, "conversation") &&
		(strings.Contains(message, "not exist") ||
			strings.Contains(message, "not found") ||
			strings.Contains(message, "invalid")) {
		return true
	}
	return strings.Contains(body, "conversation") &&
		(strings.Contains(body, "not exist") ||
			strings.Contains(body, "not found") ||
			strings.Contains(body, "invalid"))
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

func BuildPrompt(summary Summary, keepConversation bool) string {
	if keepConversation {
		return buildKeepConversationPrompt(summary)
	}
	return buildInitialPrompt(summary)
}

func buildInitialPrompt(summary Summary) string {
	return strings.TrimSpace(fmt.Sprintf(`你是一名资深网络排障工程师，请根据 netbee 抓包结果分析问题。

硬约束：
1. 你必须结合本次请求附带的抓包文件原文进行分析，不能只依据摘要下结论。
2. 如果摘要信息与抓包文件原文不一致，必须以抓包文件原文为准。
3. 你的结论中必须引用抓包文件原文里能够支撑判断的现象，例如协议分布、报文方向、TCP 标志、重传、RST、DROP、函数链路、进程信息、时间顺序等。
4. 如果抓包文件原文不足以支撑某个结论，必须明确写“证据不足”或“仍需进一步抓包验证”，不能把猜测写成确定结论。
5. 不允许脱离抓包文件内容泛泛而谈，不允许只重复摘要，不允许输出与抓包证据无关的模板化建议。
6. 你输出的“关键证据”和“综合判断”必须体现你确实分析了抓包文件原文，而不是只重述摘要。
7. 如果本次请求中同时提供了摘要和抓包文件原文，摘要仅用于帮助你快速定位重点，最终判断必须以抓包文件原文为依据。

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

func buildKeepConversationPrompt(summary Summary) string {
	return strings.TrimSpace(fmt.Sprintf(`你是一名资深网络排障工程师，当前不是首次分析，而是基于之前会话继续诊断同一个网络问题。

硬约束：
1. 你必须结合当前会话中的历史结论，以及本次请求附带的抓包文件原文共同分析，不能只依据历史结论或本地摘要下结论。
2. 如果历史结论、本地摘要与本次抓包文件原文不一致，必须优先以本次抓包文件原文为准，并明确指出哪些旧结论需要修正。
3. 你必须明确说明：本次结论相较于上次是“延续”“修正”还是“推翻”，不能省略。
4. 你的结论中必须引用本次抓包文件原文里能够支撑判断的现象，例如协议分布、报文方向、TCP 标志、重传、RST、DROP、函数链路、进程信息、时间顺序等。
5. 如果本次抓包文件原文不足以推翻或确认上次判断，必须明确写“证据不足”或“仍需进一步验证”，不能把猜测写成确定结论。
6. 不允许脱离本次抓包文件内容泛泛而谈，不允许只重复历史结论，不允许只重述摘要。
7. “关键证据”“与上次相比”“综合判断”这三部分必须体现你确实分析了本次上传的抓包文件原文。

你必须严格按下面的 Markdown 模板输出，标题名称、标题层级、分隔线都不要改，不能缺少任何章节，不能输出模板之外的额外前言、后记或客套话。

固定格式要求：
1. 必须包含且仅按以下顺序输出这些一级/二级标题：
   - ## 0. 历史结论与本次变化
   - ## 1. 本次抓包的新增现象
   - ## 2. 与上一轮判断相比的变化
   - ## 3. 当前最可能的根因（按概率排序）
   - ## 4. 关键证据
   - ## 5. 建议的下一步排查
   - ## 6. 风险与影响判断
   - # 结论
   - ## 综合判断
2. 在 # 结论 之前必须单独输出一行 ---
3. 在 ## 综合判断 章节末尾必须再单独输出一行 ---
4. # 结论 下必须先写 ## 综合判断
5. ## 综合判断 下必须包含三个固定三级标题：
   - ### 与上次相比
   - ### 已知异常
   - ### 最可能根因
6. ### 最可能根因 下必须输出编号列表 1. 2. 3. 4.
7. 不要把“综合判断”写成“综合结论”或其他近义词，必须严格使用 ## 综合判断
8. 不要使用代码块包裹全文
9. 如果历史会话中已有结论，本次必须显式说明“延续/修正/推翻”中的哪一种，不能省略
10. 如果本次抓包不足以推翻上一轮结论，优先输出“延续并增强证据”，不要轻易完全改判

请直接按下面模板产出内容：

## 0. 历史结论与本次变化
[先简要概述上一轮主要结论，再说明本次新增抓包相对上次的主要变化]

## 1. 本次抓包的新增现象
[正文]

## 2. 与上一轮判断相比的变化
[明确写出哪些判断被延续、哪些被修正、哪些被推翻]

## 3. 当前最可能的根因（按概率排序）
[正文]

## 4. 关键证据
[正文]

## 5. 建议的下一步排查
[正文]

## 6. 风险与影响判断
[正文]

---

# 结论

## 综合判断
[先给 1-2 句总判断，必须体现这是一次续查，而不是首次分析]

### 与上次相比
- [延续点1]
- [修正点1]
- [仍待确认点1]

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
