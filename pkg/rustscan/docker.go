package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func main() {
	//currentDir, err := os.Getwd()
	//if err != nil {
	//	panic(err)
	//}
	currentDir := "/Users/cc11001100/github/cyberspacesec/go-rustscan/"

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		panic(err)
	}

	// 配置容器参数
	config := &container.Config{
		Image: "rustscan/rustscan:latest",
		Cmd: []string{
			"-a", "114.114.114.114",
			//"--",
			//"--output-format", "json",
			//"--output-filename", "/output/result.json",
			"--",
			"-oX", "/output/result.xml", // 修正为nmap支持的XML输出
		},
		Tty: false, // 必须关闭 TTY 以正确捕获日志流
	}

	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/output", filepath.ToSlash(currentDir)),
		},
		AutoRemove: true, // 保持自动删除配置
	}

	// 创建容器
	resp, err := cli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		nil,
		nil,
		"",
	)
	if err != nil {
		panic(fmt.Errorf("创建容器失败: %v", err))
	}

	// 启动容器
	if err := cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{}); err != nil {
		panic(fmt.Errorf("启动容器失败: %v", err))
	}

	// 实时获取日志流
	logsReader, err := cli.ContainerLogs(
		context.Background(),
		resp.ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,  // 持续跟踪日志输出
			Timestamps: false, // 不需要时间戳
			Details:    false, // 不显示额外细节
		},
	)
	if err != nil {
		panic(fmt.Errorf("获取日志流失败: %v", err))
	}
	defer logsReader.Close()

	// 使用通道协调日志输出和等待操作
	done := make(chan error)
	go func() {
		// 将日志实时输出到控制台
		_, err = io.Copy(os.Stdout, logsReader)
		done <- err
	}()

	// 等待容器退出
	statusCh, errCh := cli.ContainerWait(
		context.Background(),
		resp.ID,
		container.WaitConditionNotRunning,
	)

	select {
	case err := <-errCh:
		panic(fmt.Errorf("等待容器失败: %v", err))
	case status := <-statusCh:
		if status.StatusCode != 0 {
			panic(fmt.Errorf("容器异常退出，状态码: %d", status.StatusCode))
		}
	}

	// 等待日志输出完成
	if err := <-done; err != nil && err != io.EOF {
		panic(fmt.Errorf("日志流错误: %v", err))
	}

	// XML文件路径
	xmlFilePath := filepath.Join(currentDir, "result.xml")
	// JSON文件路径
	jsonFilePath := filepath.Join(currentDir, "result.json")

	// 转换XML到JSON
	fmt.Println("\n开始转换XML到JSON...")
	if err := ConvertXMLToJSON(xmlFilePath, jsonFilePath); err != nil {
		panic(fmt.Errorf("转换XML到JSON失败: %v", err))
	}

	fmt.Println("扫描完成！结果已保存到:", jsonFilePath)
}
