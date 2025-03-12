package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberspacesec/go-rustscan/pkg/rustscan"
	"github.com/spf13/cobra"
)

var (
	targets    string
	ports      string
	rateLimit  int
	timeout    int
	nmapFlags  []string
	outputFile string
	format     string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute a port scan",
	Long: `Execute a port scan using RustScan. This command allows you to
directly scan targets without starting the HTTP server. It provides
all the core functionality of RustScan with additional output formats.`,
	Run: func(cmd *cobra.Command, args []string) {
		if targets == "" {
			log.Fatal("必须指定扫描目标")
		}

		// 创建临时输出目录
		tempDir := filepath.Join(os.TempDir(), "go-rustscan-"+fmt.Sprint(os.Getpid()))
		if err := os.MkdirAll(tempDir, 0755); err != nil {
			log.Fatalf("创建临时目录失败: %v", err)
		}
		defer os.RemoveAll(tempDir)

		// 准备Docker客户端
		docker, err := rustscan.NewDockerRunner()
		if err != nil {
			log.Fatalf("初始化Docker失败: %v", err)
		}

		// 构建命令参数
		args = []string{"-a", targets}
		if ports != "" {
			args = append(args, "-p", ports)
		}
		if rateLimit > 0 {
			args = append(args, "--rate", fmt.Sprint(rateLimit))
		}
		if timeout > 0 {
			args = append(args, "--timeout", fmt.Sprint(timeout))
		}

		// 添加nmap参数
		if len(nmapFlags) > 0 {
			args = append(args, "--")
			args = append(args, nmapFlags...)
		}

		// 添加XML输出
		xmlPath := filepath.Join(tempDir, "result.xml")
		args = append(args, "-oX", xmlPath)

		// 执行扫描
		if err := docker.Run(args); err != nil {
			log.Fatalf("扫描执行失败: %v", err)
		}

		// 读取结果
		result, err := rustscan.ParseNmapXML(xmlPath)
		if err != nil {
			log.Fatalf("解析扫描结果失败: %v", err)
		}

		// 根据指定格式输出结果
		var output []byte
		switch strings.ToLower(format) {
		case "json":
			output, err = json.MarshalIndent(result, "", "  ")
		default:
			log.Fatalf("不支持的输出格式: %s", format)
		}

		if err != nil {
			log.Fatalf("格式化输出失败: %v", err)
		}

		// 写入输出
		if outputFile == "" {
			fmt.Println(string(output))
		} else {
			if err := os.WriteFile(outputFile, output, 0644); err != nil {
				log.Fatalf("写入输出文件失败: %v", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&targets, "targets", "", "扫描目标，支持逗号分隔的多个目标")
	scanCmd.Flags().StringVar(&ports, "ports", "", "要扫描的端口范围 (例如: 80,443 或 1-1000)")
	scanCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "扫描速率限制")
	scanCmd.Flags().IntVar(&timeout, "timeout", 0, "超时时间（秒）")
	scanCmd.Flags().StringSliceVar(&nmapFlags, "nmap-flags", []string{}, "额外的nmap参数")
	scanCmd.Flags().StringVar(&outputFile, "output", "", "输出文件路径")
	scanCmd.Flags().StringVar(&format, "format", "json", "输出格式 (支持: json)")

	scanCmd.MarkFlagRequired("targets")
}
