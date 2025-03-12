package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// 定义MCP通知类型
type MCPNotificationType string

const (
	MCPScanStarted   MCPNotificationType = "scan_started"
	MCPScanCompleted MCPNotificationType = "scan_completed"
	MCPScanFailed    MCPNotificationType = "scan_failed"
)

// MCPPayload 表示从go-rustscan接收到的MCP数据
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

// ScanRequest 表示扫描请求参数
type ScanRequest struct {
	Targets     string   `json:"targets"`
	Ports       string   `json:"ports,omitempty"`
	RateLimit   int      `json:"rate_limit,omitempty"`
	Timeout     int      `json:"timeout,omitempty"`
	NmapOptions []string `json:"nmap_options,omitempty"`
	MCPEndpoint string   `json:"mcp_endpoint,omitempty"`
	MCPEnabled  bool     `json:"mcp_enabled,omitempty"`
	MCPApiKey   string   `json:"mcp_api_key,omitempty"`
}

// AI助手应答结构
type AIResponse struct {
	Analysis string `json:"analysis"`
	Summary  string `json:"summary"`
	Action   string `json:"recommended_action,omitempty"`
}

// 主入口
func main() {
	// 设置HTTP服务器，处理来自go-rustscan的MCP通知
	http.HandleFunc("/api/mcp/notification", handleMCPNotification)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	log.Printf("启动MCP处理服务器在端口 %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("无法启动服务器: %v", err)
	}
}

// MCP通知处理函数
func handleMCPNotification(w http.ResponseWriter, r *http.Request) {
	// 只允许POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "读取请求体失败", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 解析MCP载荷
	var payload MCPPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "解析JSON失败", http.StatusBadRequest)
		return
	}

	// 根据通知类型处理
	var aiResponse AIResponse

	switch payload.Type {
	case MCPScanStarted:
		aiResponse = handleScanStarted(payload)
	case MCPScanCompleted:
		aiResponse = handleScanCompleted(payload)
	case MCPScanFailed:
		aiResponse = handleScanFailed(payload)
	default:
		http.Error(w, "未知的通知类型", http.StatusBadRequest)
		return
	}

	// 返回AI助手的分析结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aiResponse)

	// 记录处理日志
	log.Printf("处理了 %s 类型的MCP通知，扫描ID: %s\n", payload.Type, payload.ScanID)
}

// 处理扫描开始通知
func handleScanStarted(payload MCPPayload) AIResponse {
	return AIResponse{
		Analysis: fmt.Sprintf("已开始对目标 %s 的端口 %s 扫描",
			payload.Request.Targets,
			getPortsInfo(payload.Request)),
		Summary: "扫描任务已加入队列并开始处理",
		Action:  "等待扫描完成，稍后将收到结果通知",
	}
}

// 处理扫描完成通知
func handleScanCompleted(payload MCPPayload) AIResponse {
	// 这里可以添加AI逻辑，分析扫描结果
	// 例如：识别开放端口、推断服务、评估风险等

	// 示例分析逻辑
	portCount := countOpenPorts(payload.Result)
	targets := payload.Request.Targets

	analysis := fmt.Sprintf("扫描发现目标 %s 上有 %d 个开放端口", targets, portCount)
	if portCount > 10 {
		analysis += "。开放端口数量较多，建议检查不必要的服务。"
	} else if portCount == 0 {
		analysis += "。未发现开放端口，可能存在防火墙阻断或目标不可达。"
	} else {
		analysis += "。建议检查这些端口上运行的服务版本和安全状况。"
	}

	return AIResponse{
		Analysis: analysis,
		Summary:  fmt.Sprintf("扫描完成，耗时 %d 毫秒，发现 %d 个开放端口", payload.ExecutionMS, portCount),
		Action:   generateRecommendedAction(portCount, payload.Result),
	}
}

// 处理扫描失败通知
func handleScanFailed(payload MCPPayload) AIResponse {
	return AIResponse{
		Analysis: fmt.Sprintf("扫描失败，错误信息: %s", payload.Error),
		Summary:  "无法完成对目标的扫描，请检查错误信息和网络连接",
		Action:   "建议检查目标可达性，或调整扫描参数后重试",
	}
}

// 辅助函数：获取端口信息文本
func getPortsInfo(req ScanRequest) string {
	if req.Ports == "" {
		return "默认端口"
	}
	return req.Ports
}

// 辅助函数：计算开放端口数量（示例实现）
func countOpenPorts(result interface{}) int {
	// 实际实现需要解析rustscan/nmap结果格式
	// 这里仅为示例

	// 假设result是一个map，其中包含hosts字段，为数组
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return 0
	}

	hosts, ok := resultMap["hosts"].([]interface{})
	if !ok {
		return 0
	}

	totalPorts := 0

	for _, host := range hosts {
		hostMap, ok := host.(map[string]interface{})
		if !ok {
			continue
		}

		ports, ok := hostMap["ports"].(map[string]interface{})
		if !ok {
			continue
		}

		portList, ok := ports["ports"].([]interface{})
		if !ok {
			continue
		}

		totalPorts += len(portList)
	}

	return totalPorts
}

// 辅助函数：生成建议措施
func generateRecommendedAction(portCount int, result interface{}) string {
	if portCount == 0 {
		return "考虑使用更广泛的端口范围或检查目标主机可达性"
	} else if portCount > 10 {
		return "建议进行服务版本扫描，并限制不必要的开放端口"
	} else {
		return "对发现的端口执行服务识别和漏洞扫描"
	}
}
