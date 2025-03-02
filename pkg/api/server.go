package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ScanRequest 表示扫描请求的参数
type ScanRequest struct {
	Targets     string   `json:"targets" binding:"required"` // 目标IP或域名，支持逗号分隔的多个目标
	Ports       string   `json:"ports,omitempty"`             // 要扫描的端口，例如 "80,443,8080" 或 "1-1000"
	RateLimit   int      `json:"rate_limit,omitempty"`        // 速率限制
	Timeout     int      `json:"timeout,omitempty"`           // 超时时间（秒）
	NmapOptions []string `json:"nmap_options,omitempty"`      // 额外的nmap选项
}

// ScanResponse 表示扫描响应
type ScanResponse struct {
	ID        string      `json:"id"`                 // 扫描任务ID
	Status    string      `json:"status"`             // 状态：pending, running, completed, failed
	CreatedAt time.Time   `json:"created_at"`         // 创建时间
	UpdatedAt time.Time   `json:"updated_at"`         // 更新时间
	Request   ScanRequest `json:"request"`            // 原始请求
	Result    interface{} `json:"result,omitempty"`   // 扫描结果（如果完成）
	Error     string      `json:"error,omitempty"`    // 错误信息（如果失败）
}

// Server 表示API服务器
type Server struct {
	router      *gin.Engine
	dockerCli   *client.Client
	outputDir   string
	scanResults map[string]*ScanResponse
	mutex       sync.RWMutex
}

// NewServer 创建一个新的API服务器
func NewServer(outputDir string) (*Server, error) {
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

	// 创建Gin路由器
	router := gin.Default()

	// 创建服务器实例
	server := &Server{
		router:      router,
		dockerCli:   dockerCli,
		outputDir:   outputDir,
		scanResults: make(map[string]*ScanResponse),
		mutex:       sync.RWMutex{},
	}

	// 设置路由
	server.setupRoutes()

	return server, nil
}

// setupRoutes 设置API路由
func (s *Server) setupRoutes() {
	// API版本前缀
	api := s.router.Group("/api/v1")

	// 健康检查
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 扫描相关路由
	scan := api.Group("/scan")
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
}

// Run 启动API服务器
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
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

	// 保存到内存中
	s.mutex.Lock()
	s.scanResults[id] = resp
	s.mutex.Unlock()

	// 异步执行扫描
	go s.executeScan(id, req)

	// 返回任务ID
	c.JSON(http.StatusAccepted, resp)
}

// getScanStatus 获取扫描任务状态
func (s *Server) getScanStatus(c *gin.Context) {
	id := c.Param("id")

	s.mutex.RLock()
	resp, exists := s.scanResults[id]
	s.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// getAllScans 获取所有扫描任务
func (s *Server) getAllScans(c *gin.Context) {
	s.mutex.RLock()
	results := make([]*ScanResponse, 0, len(s.scanResults))
	for _, resp := range s.scanResults {
		results = append(results, resp)
	}
	s.mutex.RUnlock()

	c.JSON(http.StatusOK, results)
}

// cancelScan 取消扫描任务
func (s *Server) cancelScan(c *gin.Context) {
	id := c.Param("id")

	s.mutex.Lock()
	resp, exists := s.scanResults[id]
	if !exists {
		s.mutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}

	// 只有处于pending或running状态的任务才能取消
	if resp.Status != "pending" && resp.Status != "running" {
		s.mutex.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法取消已完成或已失败的任务"})
		return
	}

	// 更新状态
	resp.Status = "cancelled"
	resp.UpdatedAt = time.Now()
	resp.Error = "任务被用户取消"
	s.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "扫描任务已取消"})
}

// executeScan 执行扫描任务
func (s *Server) executeScan(id string, req ScanRequest) {
	// 更新状态为running
	s.mutex.Lock()
	resp := s.scanResults[id]
	resp.Status = "running"
	resp.UpdatedAt = time.Now()
	s.mutex.Unlock()

	// 创建任务特定的输出目录
	taskDir := filepath.Join(s.outputDir, id)
	if err := os.MkdirAll(taskDir, 0755); err != nil {
		s.updateScanError(id, fmt.Sprintf("创建任务目录失败: %v", err))
		return
	}

	// 构建RustScan命令
	cmdArgs := []string{
		"-a", req.Targets,
	}

	// 添加端口参数（如果提供）
	if req.Ports != "" {
		cmdArgs = append(cmdArgs, "-p", req.Ports)
	}

	// 添加速率限制（如果提供）
	if req.RateLimit > 0 {
		cmdArgs = append(cmdArgs, "--rate", fmt.Sprintf("%d", req.RateLimit))
	}

	// 添加超时（如果提供）
	if req.Timeout > 0 {
		cmdArgs = append(cmdArgs, "--timeout", fmt.Sprintf("%d", req.Timeout))
	}

	// 添加nmap参数分隔符
	cmdArgs = append(cmdArgs, "--")

	// 添加XML输出参数
	xmlOutputPath := "/output/result.xml"
	cmdArgs = append(cmdArgs, "-oX", xmlOutputPath)

	// 添加其他nmap选项
	if len(req.NmapOptions) > 0 {
		cmdArgs = append(cmdArgs, req.NmapOptions...)
	}

	// 配置容器参数
	config := &container.Config{
		Image: "rustscan/rustscan:latest",
		Cmd:   cmdArgs,
		Tty:   false, // 必须关闭TTY以正确捕获日志流
	}

	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/output", filepath.ToSlash(taskDir)),
		},
		AutoRemove: true,
	}

	// 创建容器
	containerResp, err := s.dockerCli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		nil,
		nil,
		"",
	)
	if err != nil {
		s.updateScanError(id, fmt.Sprintf("创建容器失败: %v", err))
		return
	}

	// 启动容器
	if err := s.dockerCli.ContainerStart(context.Background(), containerResp.ID, container.StartOptions{}); err != nil {
		s.updateScanError(id, fmt.Sprintf("启动容器失败: %v", err))
		return
	}

	// 实时获取日志流
	logsReader, err := s.dockerCli.ContainerLogs(
		context.Background(),
		containerResp.ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
			Details:    false,
		},
	)
	if err != nil {
		s.updateScanError(id, fmt.Sprintf("获取日志流失败: %v", err))
		return
	}
	defer logsReader.Close()

	// 将日志保存到文件
	logFile, err := os.Create(filepath.Join(taskDir, "scan.log"))
	if err != nil {
		s.updateScanError(id, fmt.Sprintf("创建日志文件失败: %v", err))
		return
	}
	defer logFile.Close()

	// 使用通道协调日志输出和等待操作
	done := make(chan error)
	go func() {
		// 将日志实时输出到文件
		_, err = io.Copy(logFile, logsReader)
		done <- err
	}()

	// 等待容器退出
	statusCh, errCh := s.dockerCli.ContainerWait(
		context.Background(),
		containerResp.ID,
		container.WaitConditionNotRunning,
	)

	var statusErr error
select {
case err := <-errCh:
	statusErr = err
case status := <-statusCh:
	if status.StatusCode != 0 {
		statusErr = fmt.Errorf("容器异常退出，状态码: %d", status.StatusCode)
	}
}

// 等待日志输出完成
if err := <-done; err != nil && err != io.EOF {
	statusErr = fmt.Errorf("日志流错误: %v", err)
}

// 如果有错误，更新扫描状态并返回
if statusErr != nil {
	s.updateScanError(id, statusErr.Error())
	return
}

// XML文件路径
xmlFilePath := filepath.Join(taskDir, "result.xml")
// JSON文件路径
jsonFilePath := filepath.Join(taskDir, "result.json")

// 转换XML到JSON
if err := s.convertXMLToJSON(xmlFilePath, jsonFilePath); err != nil {
	s.updateScanError(id, fmt.Sprintf("转换XML到JSON失败: %v", err))
	return
}

// 读取JSON结果
jsonData, err := ioutil.ReadFile(jsonFilePath)
if err != nil {
	s.updateScanError(id, fmt.Sprintf("读取JSON结果失败: %v", err))
	return
}

// 解析JSON数据
var result interface{}
if err := json.Unmarshal(jsonData, &result); err != nil {
	s.updateScanError(id, fmt.Sprintf("解析JSON结果失败: %v", err))
	return
}

// 更新扫描结果
s.mutex.Lock()
resp = s.scanResults[id]
resp.Status = "completed"
resp.UpdatedAt = time.Now()
resp.Result = result
s.mutex.Unlock()
}

// updateScanError 更新扫描错误状态
func (s *Server) updateScanError(id string, errorMsg string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	resp, exists := s.scanResults[id]
	if !exists {
		return
	}

	resp.Status = "failed"
	resp.UpdatedAt = time.Now()
	resp.Error = errorMsg
}

// NmapRun 表示nmap扫描结果的根元素
type NmapRun struct {
	XMLName        xml.Name  `xml:"nmaprun" json:"-"`
	Scanner        string    `xml:"scanner,attr" json:"scanner"`
	Args           string    `xml:"args,attr" json:"args"`
	Start          string    `xml:"start,attr" json:"start"`
	Startstr       string    `xml:"startstr,attr" json:"startstr"`
	Version        string    `xml:"version,attr" json:"version"`
	XmlOutputVersion string   `xml:"xmloutputversion,attr" json:"xml_output_version"`
	ScanInfo       ScanInfo  `xml:"scaninfo" json:"scan_info"`
	Verbose        Verbose   `xml:"verbose" json:"verbose"`
	Debugging      Debugging `xml:"debugging" json:"debugging"`
	TaskBegin      TaskBegin `xml:"taskbegin" json:"task_begin"`
	TaskEnd        TaskEnd   `xml:"taskend" json:"task_end"`
	Hosts          []Host    `xml:"host" json:"hosts"`
	RunStats       RunStats  `xml:"runstats" json:"run_stats"`
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
	Time     string `xml:"time,attr" json:"time"`
	Timestr  string `xml:"timestr,attr" json:"timestr"`
	Summary  string `xml:"summary,attr" json:"summary"`
	Elapsed  string `xml:"elapsed,attr" json:"elapsed"`
	Exit     string `xml:"exit,attr" json:"exit"`
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