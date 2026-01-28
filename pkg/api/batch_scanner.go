package api

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// BatchScanRequest 表示批量扫描请求
type BatchScanRequest struct {
	Targets     []string `json:"targets" binding:"required"` // 目标网站列表
	Ports       string   `json:"ports,omitempty"`            // 要扫描的端口
	RateLimit   int      `json:"rate_limit,omitempty"`       // 速率限制
	Timeout     int      `json:"timeout,omitempty"`          // 超时时间（秒）
	NmapOptions []string `json:"nmap_options,omitempty"`     // nmap选项
}

// BatchScanResponse 表示批量扫描响应
type BatchScanResponse struct {
	BatchID     string                   `json:"batch_id"`     // 批量任务ID
	Status      string                   `json:"status"`       // 整体状态
	CreatedAt   time.Time                `json:"created_at"`   // 创建时间
	UpdatedAt   time.Time                `json:"updated_at"`   // 更新时间
	TotalTasks  int                      `json:"total_tasks"`  // 总任务数
	Completed   int                      `json:"completed"`    // 已完成数
	Failed      int                      `json:"failed"`       // 失败数
	InProgress  int                      `json:"in_progress"`  // 进行中数量
	TaskResults map[string]*ScanResponse `json:"task_results"` // 各任务结果
}

// BatchScanner 批量扫描处理器
type BatchScanner struct {
	server     *Server
	mutex      sync.RWMutex
	batchTasks map[string]*BatchScanResponse
}

// NewBatchScanner 创建新的批量扫描处理器
func NewBatchScanner(server *Server) *BatchScanner {
	return &BatchScanner{
		server:     server,
		mutex:      sync.RWMutex{},
		batchTasks: make(map[string]*BatchScanResponse),
	}
}

// StartBatchScan 开始批量扫描
func (bs *BatchScanner) StartBatchScan(req BatchScanRequest) (*BatchScanResponse, error) {
	// 生成批量任务ID
	batchID := fmt.Sprintf("batch-%s", time.Now().Format("20060102-150405"))

	// 创建批量任务响应
	response := &BatchScanResponse{
		BatchID:     batchID,
		Status:      "running",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		TotalTasks:  len(req.Targets),
		Completed:   0,
		Failed:      0,
		InProgress:  0,
		TaskResults: make(map[string]*ScanResponse),
	}

	// 保存批量任务信息
	bs.mutex.Lock()
	bs.batchTasks[batchID] = response
	bs.mutex.Unlock()

	// 启动后台处理
	go bs.processBatchScan(batchID, req)

	return response, nil
}

// processBatchScan 处理批量扫描任务
func (bs *BatchScanner) processBatchScan(batchID string, req BatchScanRequest) {
	var wg sync.WaitGroup

	// 创建任务通道
	taskChan := make(chan string, len(req.Targets))

	// 启动工作协程
	workerCount := bs.server.config.WorkerNum
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range taskChan {
				// 创建单个扫描任务
				scanReq := ScanRequest{
					Targets:     target,
					Ports:       req.Ports,
					RateLimit:   req.RateLimit,
					Timeout:     req.Timeout,
					NmapOptions: req.NmapOptions,
				}

				// 执行扫描
				task := &ScanTask{
					ID:      fmt.Sprintf("%s-%s", batchID, strings.ReplaceAll(target, ".", "-")),
					Request: scanReq,
					Server:  bs.server,
				}

				// 更新进行中计数
				bs.mutex.Lock()
				bs.batchTasks[batchID].InProgress++
				bs.mutex.Unlock()

				// 执行任务
				task.Execute()

				// 更新任务结果
				bs.mutex.Lock()
				if task.Response.Status == "completed" {
					bs.batchTasks[batchID].Completed++
				} else {
					bs.batchTasks[batchID].Failed++
				}
				bs.batchTasks[batchID].InProgress--
				bs.batchTasks[batchID].TaskResults[task.ID] = task.Response
				bs.batchTasks[batchID].UpdatedAt = time.Now()
				bs.mutex.Unlock()
			}
		}()
	}

	// 分发任务
	for _, target := range req.Targets {
		taskChan <- target
	}
	close(taskChan)

	// 等待所有任务完成
	wg.Wait()

	// 更新批量任务状态
	bs.mutex.Lock()
	bs.batchTasks[batchID].Status = "completed"
	bs.batchTasks[batchID].UpdatedAt = time.Now()
	bs.mutex.Unlock()
}

// GetBatchStatus 获取批量任务状态
func (bs *BatchScanner) GetBatchStatus(batchID string) (*BatchScanResponse, error) {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	response, exists := bs.batchTasks[batchID]
	if !exists {
		return nil, fmt.Errorf("批量任务 %s 不存在", batchID)
	}

	return response, nil
}
