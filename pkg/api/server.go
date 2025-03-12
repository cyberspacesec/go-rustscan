package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cyberspacesec/go-rustscan/pkg/rustscan"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ScanRequest 表示扫描请求的参数
type ScanRequest struct {
	Targets           string   `json:"targets" binding:"required"`    // 目标IP或域名，支持逗号分隔的多个目标
	Ports             string   `json:"ports,omitempty"`               // 要扫描的端口，例如 "80,443,8080" 或 "1-1000"
	RateLimit         int      `json:"rate_limit,omitempty"`          // 速率限制
	Timeout           int      `json:"timeout,omitempty"`             // 超时时间（秒）
	NmapOptions       []string `json:"nmap_options,omitempty"`        // 额外的nmap选项
	WebhookURL        string   `json:"webhook_url,omitempty"`         // 扫描完成后回调的webhook URL
	WebhookRetryCount int      `json:"webhook_retry_count,omitempty"` // webhook回调失败后的重试次数（默认3次）
	WebhookRetryDelay int      `json:"webhook_retry_delay,omitempty"` // webhook回调失败后的重试间隔（秒，默认5秒）
	MCPEndpoint       string   `json:"mcp_endpoint,omitempty"`        // MCP端点URL，用于与AI助手通信
	MCPEnabled        bool     `json:"mcp_enabled,omitempty"`         // 是否启用MCP通知
	MCPApiKey         string   `json:"mcp_api_key,omitempty"`         // MCP API密钥（如果需要）
}

// ScanResponse 表示扫描响应
type ScanResponse struct {
	ID        string      `json:"id"`               // 扫描任务ID
	Status    string      `json:"status"`           // 状态：pending, running, completed, failed, cancelled
	CreatedAt time.Time   `json:"created_at"`       // 创建时间
	UpdatedAt time.Time   `json:"updated_at"`       // 更新时间
	Request   ScanRequest `json:"request"`          // 原始请求
	Result    interface{} `json:"result,omitempty"` // 扫描结果（如果完成）
	Error     string      `json:"error,omitempty"`  // 错误信息（如果失败）
}

// ServerConfig API服务器配置
type ServerConfig struct {
	OutputDir             string        // 输出目录
	WorkerNum             int           // 工作线程数
	MaxConcurrentScans    int           // 最大并发扫描数
	QueueSize             int           // 队列大小
	RateLimit             float64       // API请求速率限制（每秒）
	RateBurst             int           // 速率突发限制
	ResultCleanupAge      time.Duration // 结果自动清理时间（超过此时间的结果将被删除）
	ResultCleanupInterval time.Duration // 清理检查间隔
}

// DefaultServerConfig 默认配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		WorkerNum:             5,
		MaxConcurrentScans:    10,
		QueueSize:             100,
		RateLimit:             10.0,
		RateBurst:             20,
		ResultCleanupAge:      7 * 24 * time.Hour, // 7天
		ResultCleanupInterval: 1 * time.Hour,      // 每小时检查一次
	}
}

// Server 表示API服务器
type Server struct {
	router      *gin.Engine
	dockerCli   *client.Client
	outputDir   string
	mutex       sync.RWMutex
	queue       *TaskQueue
	storage     Storage
	rateLimiter *RateLimiter
	config      ServerConfig
	webhook     *WebhookClient
	mcpClient   *MCPClient // MCP客户端
}

// NewServer 创建一个新的API服务器
func NewServer(outputDir string) (*Server, error) {
	return NewServerWithConfig(outputDir, DefaultServerConfig())
}

// NewServerWithConfig 使用自定义配置创建API服务器
func NewServerWithConfig(outputDir string, config ServerConfig) (*Server, error) {
	// 设置输出目录
	config.OutputDir = outputDir

	// 创建Docker客户端
	dockerCli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("创建Docker客户端失败: %v", err)
	}

	// 确保输出目录存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("创建输出目录失败: %v", err)
		}
	}

	// 创建存储
	storage, err := NewFileStorage(filepath.Join(outputDir, "scans"))
	if err != nil {
		return nil, fmt.Errorf("创建存储失败: %v", err)
	}

	// 创建Gin路由器
	router := gin.Default()

	// 创建服务器实例
	server := &Server{
		router:      router,
		dockerCli:   dockerCli,
		outputDir:   outputDir,
		mutex:       sync.RWMutex{},
		storage:     storage,
		rateLimiter: NewRateLimiter(config.RateLimit, config.RateBurst),
		config:      config,
		webhook:     NewWebhookClient(),
		mcpClient:   NewMCPClient(),
	}

	// 创建任务队列
	server.queue = NewTaskQueue(
		config.WorkerNum,
		config.MaxConcurrentScans,
		config.QueueSize,
	)

	// 启动定期清理任务
	go server.startCleanupTask()

	// 设置路由
	server.setupRoutes()

	return server, nil
}

// startCleanupTask 启动定期清理任务
func (s *Server) startCleanupTask() {
	ticker := time.NewTicker(s.config.ResultCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		count, err := s.storage.Cleanup(s.config.ResultCleanupAge)
		if err != nil {
			fmt.Printf("清理旧扫描结果失败: %v\n", err)
		} else if count > 0 {
			fmt.Printf("已清理 %d 个旧扫描结果\n", count)
		}
	}
}

// setupRoutes 设置API路由
func (s *Server) setupRoutes() {
	// API版本前缀
	api := s.router.Group("/api/v1")

	// 限流中间件
	rateLimitMiddleware := func(c *gin.Context) {
		if !s.rateLimiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}

	// 健康检查
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"queue": map[string]interface{}{
				"workers":     s.config.WorkerNum,
				"max_running": s.config.MaxConcurrentScans,
				"queue_size":  s.config.QueueSize,
			},
		})
	})

	// 扫描相关路由
	scan := api.Group("/scan", rateLimitMiddleware)
	{
		// 创建新的扫描任务
		scan.POST("/", s.createScan)

		// 获取扫描任务状态
		scan.GET("/:id", s.getScanStatus)

		// 获取所有扫描任务
		scan.GET("/", s.getAllScans)

		// 取消扫描任务（如果正在运行）
		scan.DELETE("/:id", s.cancelScan)
	}

	// 队列状态路由
	api.GET("/metrics", func(c *gin.Context) {
		metrics := s.queue.GetMetrics()
		c.JSON(http.StatusOK, metrics)
	})
}

// Run 启动API服务器
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

// Shutdown 关闭服务器
func (s *Server) Shutdown(ctx context.Context) error {
	s.queue.Shutdown()
	return nil
}

// sendMCPNotification 发送MCP通知
func (s *Server) sendMCPNotification(scan *ScanResponse, notificationType MCPNotificationType) {
	if !scan.Request.MCPEnabled || scan.Request.MCPEndpoint == "" {
		return
	}

	// 发送MCP通知
	err := s.mcpClient.SendMCPNotification(scan, scan.Request.MCPEndpoint, notificationType)
	if err != nil {
		log.Printf("发送MCP通知失败，扫描ID=%s: %v", scan.ID, err)
	} else {
		log.Printf("成功发送MCP通知，扫描ID=%s，类型=%s", scan.ID, notificationType)
	}
}

// updateScanStatus 更新扫描任务状态
func (s *Server) updateScanStatus(id string, status string, err error) {
	scan, getErr := s.storage.GetScan(id)
	if getErr != nil {
		fmt.Printf("获取扫描任务失败: %v\n", getErr)
		return
	}

	scan.Status = status
	scan.UpdatedAt = time.Now()

	if err != nil {
		scan.Error = err.Error()
	}

	if saveErr := s.storage.UpdateScan(scan); saveErr != nil {
		fmt.Printf("更新扫描任务状态失败: %v\n", saveErr)
	}

	// 根据状态发送MCP或webhook通知
	if status == "running" && scan.Request.MCPEnabled {
		// 发送扫描开始的MCP通知
		go s.sendMCPNotification(scan, MCPScanStarted)
	} else if status == "completed" {
		// 发送扫描完成的通知
		if scan.Request.WebhookURL != "" {
			go s.sendWebhookNotification(scan)
		}
		if scan.Request.MCPEnabled {
			go s.sendMCPNotification(scan, MCPScanCompleted)
		}
	} else if status == "failed" {
		// 发送扫描失败的通知
		if scan.Request.WebhookURL != "" {
			go s.sendWebhookNotification(scan)
		}
		if scan.Request.MCPEnabled {
			go s.sendMCPNotification(scan, MCPScanFailed)
		}
	}
}

// updateScanResult 更新扫描结果
func (s *Server) updateScanResult(id string, result interface{}) {
	scan, getErr := s.storage.GetScan(id)
	if getErr != nil {
		fmt.Printf("获取扫描任务失败: %v\n", getErr)
		return
	}

	scan.Result = result
	scan.UpdatedAt = time.Now()

	if saveErr := s.storage.UpdateScan(scan); saveErr != nil {
		fmt.Printf("更新扫描结果失败: %v\n", saveErr)
	}
}

// sendWebhookNotification 发送webhook通知
func (s *Server) sendWebhookNotification(scan *ScanResponse) {
	if scan.Request.WebhookURL == "" {
		return
	}

	err := s.webhook.SendWebhook(
		scan,
		scan.Request.WebhookURL,
		scan.Request.WebhookRetryCount,
		scan.Request.WebhookRetryDelay,
	)

	if err != nil {
		log.Printf("发送webhook通知失败，扫描ID=%s: %v", scan.ID, err)
	} else {
		log.Printf("成功发送webhook通知，扫描ID=%s，URL=%s", scan.ID, scan.Request.WebhookURL)
	}
}

// createScan 处理创建新扫描任务的请求
func (s *Server) createScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("无效的请求参数: %v", err)})
		return
	}

	// 生成唯一ID
	id := uuid.New().String()

	// 创建响应对象
	resp := &ScanResponse{
		ID:        id,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Request:   req,
	}

	// 保存到存储
	if err := s.storage.SaveScan(resp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("保存任务失败: %v", err)})
		return
	}

	// 创建任务并加入队列
	task := &ScanTask{
		ID:       id,
		Request:  req,
		Server:   s,
		Response: resp,
	}
	s.queue.AddTask(task)

	// 返回任务ID
	c.JSON(http.StatusAccepted, resp)
}

// getScanStatus 获取扫描任务状态
func (s *Server) getScanStatus(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.storage.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// getAllScans 获取所有扫描任务
func (s *Server) getAllScans(c *gin.Context) {
	scans, err := s.storage.GetAllScans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("获取任务列表失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, scans)
}

// cancelScan 取消扫描任务
func (s *Server) cancelScan(c *gin.Context) {
	id := c.Param("id")

	scan, err := s.storage.GetScan(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}

	// 只有处于pending或running状态的任务才能取消
	if scan.Status != "pending" && scan.Status != "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法取消已完成或已失败的任务"})
		return
	}

	// 更新状态
	scan.Status = "cancelled"
	scan.UpdatedAt = time.Now()
	scan.Error = "任务被用户取消"

	if err := s.storage.UpdateScan(scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("取消任务失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "扫描任务已取消"})
}

// runDockerScan 执行Docker扫描
func (s *Server) runDockerScan(id string, req ScanRequest) (interface{}, error) {
	// 创建任务特定的输出目录
	taskDir := filepath.Join(s.outputDir, id)
	if err := os.MkdirAll(taskDir, 0755); err != nil {
		return nil, fmt.Errorf("创建任务目录失败: %v", err)
	}

	// 构建RustScan命令
	args := []string{
		"-a", req.Targets,
	}

	// 添加端口参数（如果提供）
	if req.Ports != "" {
		args = append(args, "-p", req.Ports)
	}

	// 添加速率限制（如果提供）
	if req.RateLimit > 0 {
		args = append(args, "--rate", fmt.Sprintf("%d", req.RateLimit))
	}

	// 添加超时（如果提供）
	if req.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", req.Timeout))
	}

	// 添加nmap参数分隔符
	args = append(args, "--")

	// 添加XML输出参数
	xmlFilePath := filepath.Join(taskDir, "result.xml")
	args = append(args, "-oX", xmlFilePath)

	// 添加其他nmap选项
	args = append(args, req.NmapOptions...)

	// 准备Docker运行器
	docker, err := rustscan.NewDockerRunner()
	if err != nil {
		return nil, fmt.Errorf("初始化Docker失败: %v", err)
	}

	// 执行扫描
	if err := docker.Run(args); err != nil {
		return nil, fmt.Errorf("扫描执行失败: %v", err)
	}

	// 解析结果
	result, err := rustscan.ParseNmapXML(xmlFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析扫描结果失败: %v", err)
	}

	return result, nil
}

// NmapRun 表示nmap扫描结果的根元素
type NmapRun struct {
	XMLName          xml.Name  `xml:"nmaprun" json:"-"`
	Scanner          string    `xml:"scanner,attr" json:"scanner"`
	Args             string    `xml:"args,attr" json:"args"`
	Start            string    `xml:"start,attr" json:"start"`
	Startstr         string    `xml:"startstr,attr" json:"startstr"`
	Version          string    `xml:"version,attr" json:"version"`
	XmlOutputVersion string    `xml:"xmloutputversion,attr" json:"xml_output_version"`
	ScanInfo         ScanInfo  `xml:"scaninfo" json:"scan_info"`
	Verbose          Verbose   `xml:"verbose" json:"verbose"`
	Debugging        Debugging `xml:"debugging" json:"debugging"`
	TaskBegin        TaskBegin `xml:"taskbegin" json:"task_begin"`
	TaskEnd          TaskEnd   `xml:"taskend" json:"task_end"`
	Hosts            []Host    `xml:"host" json:"hosts"`
	RunStats         RunStats  `xml:"runstats" json:"run_stats"`
}

// ScanInfo 表示扫描信息
type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	Numservices string `xml:"numservices,attr" json:"num_services"`
	Services    string `xml:"services,attr" json:"services"`
}

// Verbose 表示详细程度
type Verbose struct {
	Level string `xml:"level,attr" json:"level"`
}

// Debugging 表示调试信息
type Debugging struct {
	Level string `xml:"level,attr" json:"level"`
}

// TaskBegin 表示任务开始
type TaskBegin struct {
	Task string `xml:"task,attr" json:"task"`
	Time string `xml:"time,attr" json:"time"`
}

// TaskEnd 表示任务结束
type TaskEnd struct {
	Task      string `xml:"task,attr" json:"task"`
	Time      string `xml:"time,attr" json:"time"`
	ExtraInfo string `xml:"extrainfo,attr" json:"extra_info"`
}

// Host 表示主机信息
type Host struct {
	Status  Status  `xml:"status" json:"status"`
	Address Address `xml:"address" json:"address"`
	Ports   Ports   `xml:"ports,omitempty" json:"ports,omitempty"`
}

// Status 表示主机状态
type Status struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl"`
}

// Address 表示地址信息
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addr_type"`
}

// Ports 表示端口信息集合
type Ports struct {
	Ports []Port `xml:"port" json:"ports"`
}

// Port 表示单个端口信息
type Port struct {
	Protocol string  `xml:"protocol,attr" json:"protocol"`
	PortID   string  `xml:"portid,attr" json:"port_id"`
	State    State   `xml:"state" json:"state"`
	Service  Service `xml:"service" json:"service"`
}

// State 表示端口状态
type State struct {
	State     string `xml:"state,attr" json:"state"`
	Reason    string `xml:"reason,attr" json:"reason"`
	ReasonTTL string `xml:"reason_ttl,attr" json:"reason_ttl"`
}

// Service 表示服务信息
type Service struct {
	Name   string `xml:"name,attr" json:"name"`
	Method string `xml:"method,attr" json:"method"`
	Conf   string `xml:"conf,attr" json:"conf"`
}

// RunStats 表示运行统计信息
type RunStats struct {
	Finished Finished `xml:"finished" json:"finished"`
	Hosts    Hosts    `xml:"hosts" json:"hosts"`
}

// Finished 表示扫描完成信息
type Finished struct {
	Time    string `xml:"time,attr" json:"time"`
	Timestr string `xml:"timestr,attr" json:"timestr"`
	Summary string `xml:"summary,attr" json:"summary"`
	Elapsed string `xml:"elapsed,attr" json:"elapsed"`
	Exit    string `xml:"exit,attr" json:"exit"`
}

// Hosts 表示主机统计信息
type Hosts struct {
	Up    string `xml:"up,attr" json:"up"`
	Down  string `xml:"down,attr" json:"down"`
	Total string `xml:"total,attr" json:"total"`
}

// convertXMLToJSON 将XML文件转换为JSON文件
func (s *Server) convertXMLToJSON(xmlFilePath, jsonFilePath string) error {
	// 读取XML文件
	xmlData, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		return fmt.Errorf("读取XML文件失败: %v", err)
	}

	// 解析XML数据
	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return fmt.Errorf("解析XML数据失败: %v", err)
	}

	// 转换为JSON
	jsonData, err := json.MarshalIndent(nmapRun, "", "  ")
	if err != nil {
		return fmt.Errorf("转换为JSON失败: %v", err)
	}

	// 写入JSON文件
	if err := ioutil.WriteFile(jsonFilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return nil
}
