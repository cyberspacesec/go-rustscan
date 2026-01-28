package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// 批量扫描结果统计
type BatchScanStats struct {
	BatchID        string
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
}

// 执行单个批量扫描任务
func executeBatchScan(targets []string, rateLimitPerBatch int, timeout int) (*BatchScanStats, error) {
	// 创建批量扫描请求
	req := map[string]interface{}{
		"targets":      targets,
		"ports":        "80,443,8080",
		"rate_limit":   rateLimitPerBatch,
		"timeout":      timeout,
		"nmap_options": []string{"-sV", "-sC"},
	}

	// 记录开始时间
	stats := &BatchScanStats{
		StartTime:  time.Now(),
		TotalTasks: len(targets),
	}

	// 转换为JSON
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// 发送请求
	resp, err := http.Post("http://localhost:8080/api/v1/scan/batch", "application/json", bytes.NewBuffer(reqData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// 获取批量任务ID
	stats.BatchID = result["batch_id"].(string)
	fmt.Printf("批量扫描任务已创建，ID: %s\n", stats.BatchID)

	// 定期检查任务状态
	for {
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/api/v1/scan/batch/%s", stats.BatchID))
		if err != nil {
			return nil, err
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		var status map[string]interface{}
		if err := json.Unmarshal(body, &status); err != nil {
			return nil, err
		}

		// 更新统计信息
		stats.CompletedTasks = int(status["completed"].(float64))
		stats.FailedTasks = int(status["failed"].(float64))

		fmt.Printf("[%s] 任务状态: %s, 完成: %v, 失败: %v, 进行中: %v\n",
			stats.BatchID,
			status["status"],
			stats.CompletedTasks,
			stats.FailedTasks,
			status["in_progress"],
		)

		// 如果任务完成，退出循环
		if status["status"] == "completed" {
			stats.EndTime = time.Now()
			stats.Duration = stats.EndTime.Sub(stats.StartTime)
			break
		}

		// 等待2秒后再次检查
		time.Sleep(2 * time.Second)
	}

	return stats, nil
}

func main() {
	// 测试参数
	concurrentBatches := []int{1, 2, 4, 8} // 并发批次数
	targetsPerBatch := 50                  // 每批任务数
	rateLimitPerBatch := 1000              // 每批速率限制
	timeout := 5                           // 超时时间（秒）

	// 测试结果统计
	var allStats []*BatchScanStats
	var mutex sync.Mutex

	// 对不同并发数进行测试
	for _, concurrentNum := range concurrentBatches {
		fmt.Printf("\n开始测试 %d 并发批次...\n", concurrentNum)
		startTime := time.Now()

		// 创建等待组
		var wg sync.WaitGroup
		wg.Add(concurrentNum)

		// 启动并发批次
		for i := 0; i < concurrentNum; i++ {
			go func(batchIndex int) {
				defer wg.Done()

				// 生成测试目标
				targets := make([]string, targetsPerBatch)
				for j := 0; j < targetsPerBatch; j++ {
					targets[j] = fmt.Sprintf("test-batch%d-target%d.com", batchIndex+1, j+1)
				}

				// 执行批量扫描
				stats, err := executeBatchScan(targets, rateLimitPerBatch, timeout)
				if err != nil {
					fmt.Printf("批次 %d 执行失败: %v\n", batchIndex+1, err)
					return
				}

				// 保存统计结果
				mutex.Lock()
				allStats = append(allStats, stats)
				mutex.Unlock()
			}(i)
		}

		// 等待所有批次完成
		wg.Wait()
		totalDuration := time.Since(startTime)

		// 输出本轮测试统计
		fmt.Printf("\n%d 并发批次测试完成:\n", concurrentNum)
		fmt.Printf("总耗时: %v\n", totalDuration)
		fmt.Printf("平均每批次耗时: %v\n", totalDuration/time.Duration(concurrentNum))
	}

	// 输出总体统计信息
	fmt.Println("\n总体测试统计:")
	for _, stats := range allStats {
		fmt.Printf("批次 %s:\n", stats.BatchID)
		fmt.Printf("  耗时: %v\n", stats.Duration)
		fmt.Printf("  总任务数: %d\n", stats.TotalTasks)
		fmt.Printf("  完成任务数: %d\n", stats.CompletedTasks)
		fmt.Printf("  失败任务数: %d\n", stats.FailedTasks)
		fmt.Printf("  成功率: %.2f%%\n", float64(stats.CompletedTasks)/float64(stats.TotalTasks)*100)
	}
}
