#!/bin/bash

# 性能测试脚本

# 测试配置
API_HOST="http://localhost:8080"
CONCURRENCY=(5 10 20)    # 并发用户数，降低并发量
REQUESTS=100             # 每个测试的总请求数，减少总请求数
TIMEOUT=30               # 请求超时时间（秒）

# 创建测试数据目录
TEST_DIR="performance_test_results"
mkdir -p "$TEST_DIR"

# 测试时间戳
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 单个扫描任务测试
echo "开始单个扫描任务性能测试..."
for c in "${CONCURRENCY[@]}"; do
    echo "测试并发数: $c"
    
    # 准备测试数据
    TEST_DATA='{"targets":"example.com","ports":"80,443","rate_limit":1000}'
    
    # 执行测试
    ab -n $REQUESTS -c $c -s $TIMEOUT -p /dev/stdin -T 'application/json' \
       "$API_HOST/api/v1/scan/" << EOF > "$TEST_DIR/single_scan_c${c}_${TIMESTAMP}.txt"
$TEST_DATA
EOF
    
    # 检查ab命令是否成功执行
    if [ $? -ne 0 ]; then
        echo "单个扫描测试失败，并发数: $c"
        continue
    fi
    
    echo "完成并发数 $c 的测试"
    sleep 5  # 等待系统冷却
done

# 批量扫描任务测试
echo "\n开始批量扫描任务性能测试..."
for c in "${CONCURRENCY[@]}"; do
    echo "测试并发数: $c"
    
    # 准备批量测试数据
    BATCH_TEST_DATA='{"targets":["example1.com","example2.com","example3.com"],"ports":"80,443","rate_limit":1000}'
    
    # 执行测试
    ab -n $REQUESTS -c $c -s $TIMEOUT -p /dev/stdin -T 'application/json' \
       "$API_HOST/api/v1/scan/batch" << EOF > "$TEST_DIR/batch_scan_c${c}_${TIMESTAMP}.txt"
$BATCH_TEST_DATA
EOF
    
    # 检查ab命令是否成功执行
    if [ $? -ne 0 ]; then
        echo "批量扫描测试失败，并发数: $c"
        continue
    fi
    
    echo "完成并发数 $c 的测试"
    sleep 5  # 等待系统冷却
done

# 分析结果
echo "\n性能测试完成。结果保存在 $TEST_DIR 目录下。"
echo "测试时间: $(date)"

# 显示结果摘要
echo "\n=== 测试结果摘要 ==="
for file in "$TEST_DIR"/*_${TIMESTAMP}.txt; do
    echo "\n文件: $(basename "$file")"
    echo "请求成功率:"
    grep "Complete requests" "$file"
    echo "平均响应时间:"
    grep "Time per request" "$file" | head -n 1
    echo "失败请求数:"
    grep "Failed requests" "$file"
done