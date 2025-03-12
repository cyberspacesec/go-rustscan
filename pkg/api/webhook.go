package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// WebhookClient 处理webhook调用
type WebhookClient struct {
	client *http.Client
}

// NewWebhookClient 创建新的webhook客户端
func NewWebhookClient() *WebhookClient {
	return &WebhookClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// WebhookPayload 表示发送到webhook的数据
type WebhookPayload struct {
	ScanID      string                 `json:"scan_id"`
	Status      string                 `json:"status"`
	CompletedAt time.Time              `json:"completed_at"`
	Request     ScanRequest            `json:"request"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ExecutionMS int64                  `json:"execution_ms"` // 执行耗时（毫秒）
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SendWebhook 发送webhook通知
func (w *WebhookClient) SendWebhook(scan *ScanResponse, webhookURL string, retryCount int, retryDelay int) error {
	if webhookURL == "" {
		return nil // 没有提供webhook URL，直接返回
	}

	// 设置默认重试参数
	if retryCount <= 0 {
		retryCount = 3
	}
	if retryDelay <= 0 {
		retryDelay = 5
	}

	// 准备webhook载荷
	executionTime := scan.UpdatedAt.Sub(scan.CreatedAt).Milliseconds()
	payload := WebhookPayload{
		ScanID:      scan.ID,
		Status:      scan.Status,
		CompletedAt: scan.UpdatedAt,
		Request:     scan.Request,
		Result:      scan.Result,
		Error:       scan.Error,
		ExecutionMS: executionTime,
		Metadata: map[string]interface{}{
			"version": "1.0",
			"source":  "go-rustscan",
		},
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化webhook数据失败: %v", err)
	}

	// 发送请求（带重试）
	var lastError error
	for attempt := 0; attempt <= retryCount; attempt++ {
		if attempt > 0 {
			log.Printf("Webhook重试 #%d, URL: %s, 扫描ID: %s", attempt, webhookURL, scan.ID)
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}

		lastError = w.sendRequest(webhookURL, jsonData)
		if lastError == nil {
			log.Printf("Webhook发送成功, URL: %s, 扫描ID: %s", webhookURL, scan.ID)
			return nil
		}
	}

	log.Printf("Webhook发送失败, URL: %s, 扫描ID: %s, 错误: %v", webhookURL, scan.ID, lastError)
	return fmt.Errorf("webhook发送失败（已重试%d次）: %v", retryCount, lastError)
}

// sendRequest 执行实际的HTTP请求
func (w *WebhookClient) sendRequest(webhookURL string, jsonData []byte) error {
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建webhook请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Go-RustScan/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送webhook请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook服务器返回异常状态码: %d", resp.StatusCode)
	}

	return nil
}
