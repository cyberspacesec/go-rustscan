package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cyberspacesec/go-rustscan/pkg/api"
)

func main() {
	// 获取当前工作目录作为输出目录
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("获取工作目录失败: %v", err)
	}

	// 创建输出目录
	outputDir := filepath.Join(workDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	// 创建API服务器
	server, err := api.NewServer(outputDir)
	if err != nil {
		log.Fatalf("创建API服务器失败: %v", err)
	}

	// 启动服务器
	port := ":8080"
	fmt.Printf("API服务器正在监听端口%s...\n", port)
	if err := server.Run(port); err != nil {
		log.Fatalf("启动API服务器失败: %v", err)
	}
}