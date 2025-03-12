package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberspacesec/go-rustscan/pkg/api"
	"github.com/spf13/cobra"
)

var (
	outputDir          string
	workerNum          int
	maxConcurrentScans int
	queueSize          int
	rateLimitValue     float64
	resultCleanupDays  int
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP API server",
	Long: `Start the HTTP API server that provides RESTful endpoints for
RustScan operations. The server provides endpoints for creating scan
tasks, monitoring their progress, and retrieving results.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果没有指定输出目录，使用当前工作目录下的output文件夹
		if outputDir == "" {
			workDir, err := os.Getwd()
			if err != nil {
				log.Fatalf("获取工作目录失败: %v", err)
			}
			outputDir = filepath.Join(workDir, "output")
		}

		// 创建输出目录
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Fatalf("创建输出目录失败: %v", err)
		}

		// 创建服务器配置
		config := api.DefaultServerConfig()
		config.WorkerNum = workerNum
		config.MaxConcurrentScans = maxConcurrentScans
		config.QueueSize = queueSize
		config.RateLimit = rateLimitValue
		config.ResultCleanupAge = time.Duration(resultCleanupDays) * 24 * time.Hour

		// 创建API服务器
		server, err := api.NewServerWithConfig(outputDir, config)
		if err != nil {
			log.Fatalf("创建API服务器失败: %v", err)
		}

		// 启动服务器
		fmt.Printf("API服务器正在监听端口%s...\n", port)
		fmt.Printf("工作线程数: %d, 最大并发扫描: %d, 队列大小: %d\n",
			workerNum, maxConcurrentScans, queueSize)

		if err := server.Run(":" + port); err != nil {
			log.Fatalf("启动API服务器失败: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// 基本配置
	serveCmd.Flags().StringVar(&outputDir, "output-dir", "", "directory to store scan results (default is ./output)")

	// 性能相关配置
	serveCmd.Flags().IntVar(&workerNum, "workers", 5, "number of worker threads")
	serveCmd.Flags().IntVar(&maxConcurrentScans, "max-concurrent", 10, "maximum number of concurrent scans")
	serveCmd.Flags().IntVar(&queueSize, "queue-size", 100, "size of the task queue")

	// 限流和清理配置
	serveCmd.Flags().Float64Var(&rateLimitValue, "rate-limit", 10.0, "API rate limit in requests per second")
	serveCmd.Flags().IntVar(&resultCleanupDays, "cleanup-days", 7, "automatically clean up scan results older than this many days")
}
