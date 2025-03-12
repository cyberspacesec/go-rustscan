package api

import (
	"log"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ScanTask 表示一个扫描任务
type ScanTask struct {
	ID       string
	Request  ScanRequest
	Server   *Server
	Response *ScanResponse
}

// Execute 执行扫描任务
func (t *ScanTask) Execute() {
	// 更新状态为运行中
	t.Server.updateScanStatus(t.ID, "running", nil)

	// 执行Docker扫描
	result, err := t.Server.runDockerScan(t.ID, t.Request)

	// 根据结果更新状态
	if err != nil {
		t.Server.updateScanStatus(t.ID, "failed", err)
	} else {
		t.Server.updateScanStatus(t.ID, "completed", nil)
		t.Server.updateScanResult(t.ID, result)
	}
}

// TaskQueue 任务队列结构
type TaskQueue struct {
	tasks      chan *ScanTask
	workerNum  int
	maxRunning int
	sem        chan struct{} // 信号量控制并发
	wg         sync.WaitGroup
	ctx        chan struct{} // 用于关闭队列
	metrics    *QueueMetrics
}

// QueueMetrics 队列相关指标
type QueueMetrics struct {
	RunningTasks   int64
	CompletedTasks int64
	FailedTasks    int64
	QueuedTasks    int64
	mutex          sync.RWMutex
}

// NewTaskQueue 创建任务队列
func NewTaskQueue(workerNum int, maxRunning int, queueSize int) *TaskQueue {
	q := &TaskQueue{
		tasks:      make(chan *ScanTask, queueSize),
		workerNum:  workerNum,
		maxRunning: maxRunning,
		sem:        make(chan struct{}, maxRunning),
		ctx:        make(chan struct{}),
		metrics:    &QueueMetrics{},
	}

	// 启动工作线程
	for i := 0; i < workerNum; i++ {
		go q.worker(i)
	}

	// 启动指标收集
	go q.collectMetrics()

	return q
}

// worker 工作线程函数
func (q *TaskQueue) worker(id int) {
	log.Printf("工作线程 #%d 已启动", id)
	for {
		select {
		case <-q.ctx:
			log.Printf("工作线程 #%d 正在关闭", id)
			return
		case task, ok := <-q.tasks:
			if !ok {
				log.Printf("工作线程 #%d 的任务通道已关闭", id)
				return
			}

			// 获取信号量，限制并发
			q.sem <- struct{}{}
			log.Printf("工作线程 #%d 开始执行任务 %s", id, task.ID)

			// 更新指标
			q.metrics.incrementRunning()

			// 执行任务
			start := time.Now()
			task.Execute()
			elapsed := time.Since(start)

			// 任务完成，更新指标
			if task.Response.Status == "completed" {
				q.metrics.incrementCompleted()
			} else if task.Response.Status == "failed" {
				q.metrics.incrementFailed()
			}
			q.metrics.decrementRunning()

			// 释放信号量
			<-q.sem
			log.Printf("工作线程 #%d 完成任务 %s，耗时: %v", id, task.ID, elapsed)
		}
	}
}

// AddTask 添加任务到队列
func (q *TaskQueue) AddTask(task *ScanTask) {
	q.metrics.incrementQueued()
	q.tasks <- task
}

// Shutdown 关闭队列
func (q *TaskQueue) Shutdown() {
	close(q.ctx)
	close(q.tasks)
	q.wg.Wait()
	log.Println("任务队列已关闭")
}

// GetMetrics 获取队列指标
func (q *TaskQueue) GetMetrics() QueueMetrics {
	q.metrics.mutex.RLock()
	defer q.metrics.mutex.RUnlock()
	return *q.metrics
}

// 指标相关方法
func (m *QueueMetrics) incrementRunning() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.RunningTasks++
}

func (m *QueueMetrics) decrementRunning() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.RunningTasks--
}

func (m *QueueMetrics) incrementCompleted() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.CompletedTasks++
}

func (m *QueueMetrics) incrementFailed() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.FailedTasks++
}

func (m *QueueMetrics) incrementQueued() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.QueuedTasks++
}

func (m *QueueMetrics) decrementQueued() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.QueuedTasks--
}

// 周期性收集和输出指标
func (q *TaskQueue) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.ctx:
			return
		case <-ticker.C:
			metrics := q.GetMetrics()
			log.Printf("队列状态: 运行中任务: %d, 已完成任务: %d, 失败任务: %d, 队列中任务: %d",
				metrics.RunningTasks, metrics.CompletedTasks, metrics.FailedTasks, metrics.QueuedTasks)
		}
	}
}

// RateLimiter 速率限制器
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

// Allow 检查是否允许请求
func (r *RateLimiter) Allow() bool {
	return r.limiter.Allow()
}

// Wait 等待允许请求
func (r *RateLimiter) Wait() {
	r.limiter.Wait(nil)
}
