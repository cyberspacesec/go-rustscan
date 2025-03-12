package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// MCPClient 处理MCP协议调用，用于与AI助手通信
type MCPClient struct {
	client *http.Client
}

// NewMCPClient 创建新的MCP客户端
func NewMCPClient() *MCPClient {
	return &MCPClient{
		client: &http.Client{
			Timeout: 60 * time.Second, // MCP可能需要更长的处理时间
		},
	}
}

// MCPNotificationType 定义MCP通知类型
type MCPNotificationType string

const (
	// MCPScanStarted 扫描开始
	MCPScanStarted MCPNotificationType = "scan_started"
	// MCPScanCompleted 扫描完成
	MCPScanCompleted MCPNotificationType = "scan_completed"
	// MCPScanFailed 扫描失败
	MCPScanFailed MCPNotificationType = "scan_failed"
)

// MCPPayload 表示发送到MCP的数据
type MCPPayload struct {
	Type        MCPNotificationType    `json:"type"`
	ScanID      string                 `json:"scan_id"`
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Request     ScanRequest            `json:"request"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ExecutionMS int64                  `json:"execution_ms,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SendMCPNotification 发送MCP通知
func (m *MCPClient) SendMCPNotification(scan *ScanResponse, mcpEndpoint string, notificationType MCPNotificationType) error {
	if mcpEndpoint == "" {
		return nil // 没有提供MCP端点，直接返回
	}

	// 准备MCP载荷
	executionTime := scan.UpdatedAt.Sub(scan.CreatedAt).Milliseconds()
	payload := MCPPayload{
		Type:        notificationType,
		ScanID:      scan.ID,
		Status:      scan.Status,
		Timestamp:   time.Now(),
		Request:     scan.Request,
		Result:      scan.Result,
		Error:       scan.Error,
		ExecutionMS: executionTime,
		Metadata: map[string]interface{}{
			"version":      "1.0",
			"source":       "go-rustscan",
			"notification": string(notificationType),
		},
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化MCP数据失败: %v", err)
	}

	// 发送MCP请求
	lastError := m.sendMCPRequest(mcpEndpoint, jsonData)
	if lastError != nil {
		log.Printf("MCP通知发送失败, 端点: %s, 扫描ID: %s, 错误: %v", mcpEndpoint, scan.ID, lastError)
		return fmt.Errorf("MCP通知发送失败: %v", lastError)
	}

	log.Printf("MCP通知发送成功, 端点: %s, 类型: %s, 扫描ID: %s", mcpEndpoint, notificationType, scan.ID)
	return nil
}

// sendMCPRequest 执行实际的MCP HTTP请求
func (m *MCPClient) sendMCPRequest(mcpEndpoint string, jsonData []byte) error {
	req, err := http.NewRequest("POST", mcpEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建MCP请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Go-RustScan/MCP-1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送MCP请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("MCP服务器返回异常状态码: %d", resp.StatusCode)
	}

	return nil
}
