# go-rustscan

Go wrapper for RustScan with HTTP API and CLI support

## 功能特性

- 提供了RustScan的HTTP API封装
- 支持命令行直接扫描
- 任务队列管理和高并发控制
- 扫描历史记录和结果持久化
- 内置速率限制和资源管理
- 支持webhook异步通知结果
- 支持MCP协议，可与各种AI助手集成

## 安装

```bash
git clone https://github.com/cyberspacesec/go-rustscan.git
cd go-rustscan
go build
```

## 使用方法

### 命令行扫描模式

直接进行端口扫描：

```bash
# 基本扫描
./go-rustscan scan --targets example.com --ports 80,443

# 高级选项
./go-rustscan scan \
  --targets example.com,another.com \
  --ports 1-1000 \
  --rate-limit 1000 \
  --timeout 5 \
  --nmap-flags="-sV,-sC" \
  --output result.json \
  --format json
```

### HTTP API 服务器模式

启动API服务器：

```bash
# 基本启动
./go-rustscan serve

# 自定义配置
./go-rustscan serve \
  --port 8080 \
  --output-dir ./results \
  --workers 10 \
  --max-concurrent 20 \
  --queue-size 200 \
  --rate-limit 15.0 \
  --cleanup-days 14
```

API服务器提供以下端点：

- `POST /api/v1/scan/` - 创建新的扫描任务
- `GET /api/v1/scan/:id` - 获取特定扫描任务的状态
- `GET /api/v1/scan/` - 获取所有扫描任务列表
- `DELETE /api/v1/scan/:id` - 取消正在运行的扫描任务
- `GET /api/v1/health` - 健康检查
- `GET /api/v1/metrics` - 队列和性能指标

### 高并发场景配置

对于高并发场景，可以通过以下参数进行优化：

- `--workers`: 工作线程数量，建议设置为CPU核心数的1-2倍
- `--max-concurrent`: 最大并发扫描数，影响Docker容器数量
- `--queue-size`: 队列大小，控制等待处理的任务数量
- `--rate-limit`: API请求速率限制（每秒请求数）
- `--cleanup-days`: 自动清理多少天前的扫描结果

性能调优示例：

```bash
# 8核CPU服务器，16GB内存配置
./go-rustscan serve --workers 16 --max-concurrent 30 --queue-size 500 --rate-limit 50.0

# 4核CPU服务器，8GB内存配置
./go-rustscan serve --workers 8 --max-concurrent 15 --queue-size 200 --rate-limit 20.0

# 低配置服务器
./go-rustscan serve --workers 4 --max-concurrent 8 --queue-size 100 --rate-limit 10.0
```

## API示例

### 创建扫描任务：

```bash
curl -X POST http://localhost:8080/api/v1/scan/ \
  -H "Content-Type: application/json" \
  -d '{
    "targets": "example.com",
    "ports": "80,443",
    "rate_limit": 1000,
    "timeout": 5,
    "nmap_options": ["-sV", "-sC"]
  }'
```

### 使用webhook异步通知：

```bash
curl -X POST http://localhost:8080/api/v1/scan/ \
  -H "Content-Type: application/json" \
  -d '{
    "targets": "example.com",
    "ports": "80,443",
    "webhook_url": "https://your-server.com/callback",
    "webhook_retry_count": 5,
    "webhook_retry_delay": 10
  }'
```

当扫描完成后，系统会向指定的webhook URL发送POST请求，内容包括：

```json
{
  "scan_id": "f8a7b4e2-c1d3-4a5b-8c9e-0f1d2a3b4c5d",
  "status": "completed",
  "completed_at": "2023-05-01T15:30:45Z",
  "request": {
    "targets": "example.com",
    "ports": "80,443"
  },
  "result": {
    "hosts": [
      {
        "address": {
          "addr": "93.184.216.34",
          "addr_type": "ipv4"
        },
        "ports": {
          "ports": [
            {
              "port_id": "80",
              "protocol": "tcp",
              "state": {
                "state": "open"
              }
            }
          ]
        }
      }
    ]
  },
  "execution_ms": 3542,
  "metadata": {
    "version": "1.0",
    "source": "go-rustscan"
  }
}
```

### 使用MCP与AI助手集成：

```bash
curl -X POST http://localhost:8080/api/v1/scan/ \
  -H "Content-Type: application/json" \
  -d '{
    "targets": "example.com",
    "ports": "80,443,8080",
    "mcp_enabled": true,
    "mcp_endpoint": "https://your-ai-assistant-endpoint.com/api",
    "mcp_api_key": "your_api_key_if_needed"
  }'
```

MCP通知会在扫描开始、完成或失败时发送，内容样例：

```json
{
  "type": "scan_completed",
  "scan_id": "f8a7b4e2-c1d3-4a5b-8c9e-0f1d2a3b4c5d",
  "status": "completed",
  "timestamp": "2023-05-01T15:30:45Z",
  "request": {
    "targets": "example.com",
    "ports": "80,443,8080"
  },
  "result": {
    // 扫描结果（与webhook格式相同）
  },
  "execution_ms": 3542,
  "metadata": {
    "version": "1.0",
    "source": "go-rustscan",
    "notification": "scan_completed"
  }
}
```

## 与AI助手集成场景

MCP集成支持以下场景：

1. **自动化安全评估**：将扫描结果直接发送给AI助手进行安全评估和风险分析
2. **智能端口识别**：AI可以根据开放端口推断可能运行的服务和潜在漏洞
3. **扫描策略建议**：基于初始扫描结果，AI可以建议后续更深入的扫描策略
4. **上下文感知通知**：AI可以根据环境上下文生成更有价值的通知
5. **自然语言交互**：通过AI助手，用户可以使用自然语言查询和解释扫描结果

## 许可证

MIT

