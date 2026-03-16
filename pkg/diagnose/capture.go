package diagnose

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"sync"
)

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// CaptureBuffer 收集抓包输出，超过阈值后自动落到临时文件。
type CaptureBuffer struct {
	mu           sync.Mutex
	memoryLimit  int64
	inMemory     bytes.Buffer
	tempFile     *os.File
	tempFilePath string
	size         int64
}

// NewCaptureBuffer 创建抓包采集缓冲区。
func NewCaptureBuffer(memoryLimit int64) *CaptureBuffer {
	if memoryLimit <= 0 {
		memoryLimit = 2 * 1024 * 1024
	}
	return &CaptureBuffer{
		memoryLimit: memoryLimit,
	}
}

// WritePlainText 写入纯文本内容，自动移除 ANSI 转义序列。
func (cb *CaptureBuffer) WritePlainText(content string) error {
	clean := ansiRegexp.ReplaceAllString(content, "")
	_, err := cb.Write([]byte(clean))
	return err
}

// Write 写入采集缓冲区。
func (cb *CaptureBuffer) Write(p []byte) (int, error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err := cb.ensureStorageLocked(int64(len(p))); err != nil {
		return 0, err
	}

	var (
		n   int
		err error
	)
	if cb.tempFile != nil {
		n, err = cb.tempFile.Write(p)
	} else {
		n, err = cb.inMemory.Write(p)
	}
	cb.size += int64(n)
	return n, err
}

func (cb *CaptureBuffer) ensureStorageLocked(extra int64) error {
	if cb.tempFile != nil {
		return nil
	}
	if cb.size+extra <= cb.memoryLimit {
		return nil
	}

	tempFile, err := os.CreateTemp("", "netbee-ai-capture-*.log")
	if err != nil {
		return err
	}
	if _, err := tempFile.Write(cb.inMemory.Bytes()); err != nil {
		tempFile.Close()
		_ = os.Remove(tempFile.Name())
		return err
	}

	cb.tempFile = tempFile
	cb.tempFilePath = tempFile.Name()
	cb.inMemory.Reset()
	return nil
}

// ReadAll 读取当前已收集的全部抓包内容。
func (cb *CaptureBuffer) ReadAll() ([]byte, error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.tempFile == nil {
		return append([]byte(nil), cb.inMemory.Bytes()...), nil
	}

	if _, err := cb.tempFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(cb.tempFile)
	if err != nil {
		return nil, err
	}
	if _, err := cb.tempFile.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return data, nil
}

// Size 返回已收集的总字节数。
func (cb *CaptureBuffer) Size() int64 {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.size
}

// TempFilePath 返回临时文件路径。
func (cb *CaptureBuffer) TempFilePath() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.tempFilePath
}

// Close 关闭并清理临时文件。
func (cb *CaptureBuffer) Close() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	var firstErr error
	if cb.tempFile != nil {
		if err := cb.tempFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if cb.tempFilePath != "" {
			if err := os.Remove(cb.tempFilePath); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
		}
		cb.tempFile = nil
		cb.tempFilePath = ""
	}
	return firstErr
}
