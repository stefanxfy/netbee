#!/bin/bash

# HTTP kprobe监控测试脚本

echo "=== HTTP kprobe监控测试 ==="
echo ""

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "错误: 此脚本需要root权限运行"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查eBPF程序是否存在
if [ ! -f "./target/netbee-http.o" ]; then
    echo "错误: eBPF程序文件不存在"
    echo "请先编译eBPF程序: make build"
    exit 1
fi

# 检查主程序是否存在
if [ ! -f "./target/netbee-http" ]; then
    echo "错误: 主程序文件不存在"
    echo "请先编译主程序: go build -o target/netbee-http cmd/main-http.go"
    exit 1
fi

echo "✓ 检查通过，开始测试..."
echo ""

# 启动HTTP监控程序（后台运行）
echo "启动HTTP监控程序..."
./target/netbee-http &
MONITOR_PID=$!

# 等待程序启动
sleep 2

echo "✓ HTTP监控程序已启动 (PID: $MONITOR_PID)"
echo ""

# 测试HTTP请求
echo "发送测试HTTP请求..."

# 使用curl发送HTTP请求
curl -s http://httpbin.org/get > /dev/null &
curl -s http://httpbin.org/post -X POST -d "test=data" > /dev/null &
curl -s http://httpbin.org/status/200 > /dev/null &

# 等待请求完成
sleep 3

echo "✓ 测试请求已发送"
echo ""

# 停止监控程序
echo "停止HTTP监控程序..."
kill $MONITOR_PID
wait $MONITOR_PID 2>/dev/null

echo "✓ 测试完成"
echo ""
echo "=== 测试总结 ==="
echo "1. kprobe/sock_sendmsg - 监控HTTP请求发送"
echo "2. kprobe/sock_recvmsg - 监控HTTP响应接收"
echo "3. 进程信息显示 - 显示发送/接收HTTP数据的进程"
echo "4. 与socket filter结合 - 提供完整的HTTP监控能力"
echo ""
echo "注意: 如果看到进程信息，说明kprobe工作正常"
echo "如果只看到网络信息，说明只有socket filter在工作"
