package rustscan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// DockerRunner 用于在Docker中运行RustScan的结构体
type DockerRunner struct {
	cli       *client.Client
	outputDir string
}

// NewDockerRunner 创建一个新的DockerRunner实例
func NewDockerRunner() (*DockerRunner, error) {
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("创建Docker客户端失败: %v", err)
	}

	return &DockerRunner{
		cli: cli,
	}, nil
}

// Run 执行RustScan扫描
func (r *DockerRunner) Run(args []string) error {
	// 配置容器参数
	config := &container.Config{
		Image: "rustscan/rustscan:latest",
		Cmd:   args,
		Tty:   false, // 必须关闭 TTY 以正确捕获日志流
	}

	// 获取当前工作目录
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("获取工作目录失败: %v", err)
	}

	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/output", filepath.ToSlash(currentDir)),
		},
		AutoRemove: true,
	}

	// 创建容器
	resp, err := r.cli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		nil,
		nil,
		"",
	)
	if err != nil {
		return fmt.Errorf("创建容器失败: %v", err)
	}

	// 启动容器
	if err := r.cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("启动容器失败: %v", err)
	}

	// 实时获取日志流
	logsReader, err := r.cli.ContainerLogs(
		context.Background(),
		resp.ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
			Details:    false,
		},
	)
	if err != nil {
		return fmt.Errorf("获取日志流失败: %v", err)
	}
	defer logsReader.Close()

	// 使用通道协调日志输出和等待操作
	done := make(chan error)
	go func() {
		_, err = io.Copy(os.Stdout, logsReader)
		done <- err
	}()

	// 等待容器退出
	statusCh, errCh := r.cli.ContainerWait(
		context.Background(),
		resp.ID,
		container.WaitConditionNotRunning,
	)

	select {
	case err := <-errCh:
		return fmt.Errorf("等待容器失败: %v", err)
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return fmt.Errorf("容器异常退出，状态码: %d", status.StatusCode)
		}
	}

	// 等待日志输出完成
	if err := <-done; err != nil && err != io.EOF {
		return fmt.Errorf("日志流错误: %v", err)
	}

	return nil
}
