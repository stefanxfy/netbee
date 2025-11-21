# NetBee

基于 eBPF 的网络全链路排查工具

## 0. 功能介绍与项目背景

### 为什么用 eBPF 开发网络链路排查工具

在实际网络排查中，我们经常遇到以下问题：

1. **安全进程 EDR 在内核中拦截网络**：传统的网络抓包工具（如 tcpdump）无法捕获内核层面的网络拦截行为，导致无法定位数据包在哪个环节被丢弃。

2. **全链路跟踪困难**：tcpdump 基于 TC（Traffic Control）模块实现抓包，只能捕获网络接口层面的数据包，无法跟踪数据包在内核网络栈中的完整路径。

3. **本地防火墙链路不可见**：无法抓取 Netfilter 框架中的处理流程，包括防火墙规则、NAT 转换等关键环节。

4. **进程关联困难**：无法直接关联网络流量与用户进程，难以定位是哪个进程产生的流量。

### 与 tcpdump 的对比

| 特性 | NetBee | tcpdump |
|------|--------|---------|
| **抓包方式** | eBPF kprobe/kretprobe | TC 模块 |
| **网络栈覆盖** | 全链路（从网卡到应用层） | 仅网络接口层 |
| **内核拦截可见** | ✅ 可捕获内核拦截点 | ❌ 不可见 |
| **Netfilter 跟踪** | ✅ 支持（PRE_ROUTING、LOCAL_IN、FORWARD、LOCAL_OUT、POST_ROUTING） | ❌ 不支持 |
| **输出格式** | ✅ 可视化表格，无需 Wireshark | ❌ 需要 Wireshark 分析 |
| **调用栈跟踪** | ✅ 支持（kfree_skb 调用栈） | ❌ 不支持 |
| **实时过滤** | ✅ 内核层过滤，性能高 | ✅ 支持 |

### 核心功能

1. **全链路网络跟踪**
   - 跟踪数据包从网卡接收（`netif_rx`）到应用层处理（`tcp_v4_rcv`、`udp_rcv`）的完整路径
   - 支持 Netfilter 五个钩子点的跟踪（PRE_ROUTING、LOCAL_IN、FORWARD、LOCAL_OUT、POST_ROUTING）
   - 显示数据包经过的内核函数链

2. **可视化输出**
   - 表格化输出，无需借助 Wireshark 分析
   - 颜色标记：RST 标志显示红色，TCP 重传显示红色，NF DROP 显示红色
   - 自动合并相同 packet ID 的数据包，显示完整路径

3. **进程信息抓取**
   - 自动关联网络流量与用户进程（PID、进程名）
   - 支持调用栈跟踪（`-kfree` 参数）

4. **TCP 重传检测**
   - 基于 Seq 和 Ack 自动识别 TCP 重传
   - 重传包显示 `[TCP Retransmission]` 标记，Seq 和 Ack 显示红色

5. **灵活的过滤功能**
   - 协议过滤（TCP、UDP、ICMP）
   - 主机过滤（源 IP、目标 IP、任意 IP）
   - 端口过滤（源端口、目标端口、任意端口）
   - 内核层过滤，性能高

6. **Netfilter 信息**
   - 显示数据包经过的 Netfilter 钩子点
   - 显示处理结果（ACCEPT、DROP、OTHER）
   - DROP 结果自动标记为红色

## 1. 项目架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     用户空间 (Go)                            │
├─────────────────────────────────────────────────────────────┤
│  cmd/main.go          - 主程序入口                          │
│  ├─ 参数解析与配置管理                                        │
│  ├─ eBPF 程序加载与链接                                       │
│  └─ Ring Buffer 事件处理                                      │
├─────────────────────────────────────────────────────────────┤
│  pkg/core/            - 核心功能模块                         │
│  ├─ event.go          - 事件结构定义与格式化                  │
│  ├─ filter.go         - 过滤配置解析                          │
│  ├─ packet_merger.go  - 数据包合并与格式化                    │
│  ├─ retransmission_   - TCP 重传检测                         │
│  │  detector.go                                                │
│  ├─ netfilter.go      - Netfilter 信息格式化                  │
│  ├─ symbol_resolver.go - 符号解析（调用栈）                   │
│  └─ protocol.go       - 协议相关工具函数                      │
├─────────────────────────────────────────────────────────────┤
│  pkg/comm/color/      - 颜色输出模块                         │
│  ├─ manager.go        - 颜色管理器                            │
│  ├─ formatter.go      - 格式化器                              │
│  └─ rules.go          - 颜色规则                              │
└─────────────────────────────────────────────────────────────┘
                            ↕ Ring Buffer
┌─────────────────────────────────────────────────────────────┐
│                   内核空间 (eBPF)                            │
├─────────────────────────────────────────────────────────────┤
│  ebpf/netbee.ebpf.c   - eBPF 程序                            │
│  ├─ kprobe 钩子点                                             │
│  │  ├─ netif_rx              - 网卡接收                       │
│  │  ├─ ip_rcv                - IP 层接收                      │
│  │  ├─ ip_local_deliver      - 本地交付                       │
│  │  ├─ tcp_v4_rcv            - TCP 接收                       │
│  │  ├─ udp_rcv               - UDP 接收                       │
│  │  ├─ dev_queue_xmit        - 设备发送                       │
│  │  └─ kfree_skb             - 数据包释放                     │
│  ├─ kretprobe 钩子点                                          │
│  │  └─ nf_hook_slow          - Netfilter 处理结果              │
│  ├─ 数据包解析                                                │
│  │  ├─ 以太网头解析（MAC 地址）                                │
│  │  ├─ IP 头解析（IP 地址、TTL）                               │
│  │  └─ TCP/UDP 头解析（端口、Seq、Ack）                        │
│  └─ 过滤与事件提交                                            │
│     ├─ 内核层过滤（协议、IP、端口）                            │
│     └─ Ring Buffer 事件提交                                   │
└─────────────────────────────────────────────────────────────┘
```

### 代码分层

#### 1. 内核层（eBPF）

**位置**: `ebpf/netbee.ebpf.c`

**职责**:
- 在内核关键网络函数处插入探针（kprobe/kretprobe）
- 解析网络数据包（以太网、IP、TCP/UDP）
- 执行内核层过滤（减少用户空间开销）
- 通过 Ring Buffer 将事件发送到用户空间

**关键函数**:
- `do_trace_skb()`: 核心的数据包解析和事件生成函数
- `apply_filters()`: 内核层过滤逻辑
- `parse_tcp_mss()`: TCP MSS 解析

#### 2. 核心层（Core）

**位置**: `pkg/core/`

**职责**:
- 事件结构定义和序列化
- 过滤配置解析和管理
- 数据包合并和格式化
- TCP 重传检测
- Netfilter 信息格式化
- 符号解析（调用栈）

**关键模块**:
- `event.go`: 定义 `SoEvent` 结构，提供事件格式化方法
- `packet_merger.go`: 合并相同 packet ID 的数据包，生成函数链
- `retransmission_detector.go`: TCP 重传检测器
- `filter.go`: 过滤配置解析

#### 3. 通信层（Comm）

**位置**: `pkg/comm/color/`

**职责**:
- 颜色输出管理
- 格式化规则定义
- 终端检测

**关键模块**:
- `manager.go`: 颜色管理器，统一管理颜色输出
- `formatter.go`: 格式化器，应用颜色规则
- `rules.go`: 颜色规则定义（RST、TTL、MAC 厂商等）

#### 4. 应用层（Cmd）

**位置**: `cmd/main.go`

**职责**:
- 命令行参数解析
- eBPF 程序加载和链接
- Ring Buffer 事件读取和处理
- 输出格式化

**关键流程**:
1. 解析命令行参数
2. 加载 eBPF 程序规范（`.o` 文件）
3. 创建 eBPF 程序集合
4. 附加 kprobe/kretprobe 到内核函数
5. 读取 Ring Buffer 事件
6. 格式化并输出

### 数据流

```
内核网络函数
    ↓
eBPF kprobe/kretprobe
    ↓
数据包解析 + 过滤
    ↓
Ring Buffer (事件)
    ↓
用户空间读取
    ↓
事件解析
    ↓
数据包合并（相同 packet ID）
    ↓
格式化输出（颜色、重传检测等）
    ↓
终端/文件输出
```

## 2. 项目构建与执行

### 环境要求

- Linux 内核版本 >= 5.8（支持 eBPF CO-RE）
- Go 1.18+
- Clang 10+（用于编译 eBPF 程序）
- LLVM（用于编译 eBPF 程序）
- 需要 root 权限运行

### 构建步骤

#### 1. 编译 eBPF 程序

使用 `just` 工具（推荐）：

```bash
# 编译 eBPF 程序
just ebpf

# 或者手动编译
clang -g -O2 -mcpu=v2 -D__TARGET_ARCH_x86 -Wunused-command-line-argument -target bpf \
    -I./ebpf/ -c ./ebpf/netbee.ebpf.c -o ./target/netbee.o
```

#### 2. 编译 Go 程序

使用 `just` 工具（推荐）：

```bash
# 编译主程序
just build

# 或者手动编译
go build -o target/netbee ./cmd/main.go
```

#### 3. 一键构建

```bash
# 同时编译 eBPF 和 Go 程序
just ebpf && just build
```

### 执行方法

#### 基本用法

```bash
# 需要 root 权限
./target/netbee -h
网络数据包监控工具 - netbee

用法:
  sudo ./target/netbee [选项]

协议过滤 (proto):
  -proto string
        过滤协议，逗号分隔 (tcp,udp,icmp)

主机过滤 (host):
  -shost string
        过滤来源主机IP地址
  -dhost string
        过滤目标主机IP地址
  -host string
        过滤主机IP地址 (来源或目标IP匹配即可)

端口过滤 (port):
  -sport int
        过滤来源端口
  -dport int
        过滤目的端口
  -port int
        过滤端口 (来源端口或目的端口匹配即可)

调试选项 (kfree):
  -kfree
        显示kfree_skb的调用栈信息

颜色输出选项:
  -no-color
        禁用颜色输出

数据包合并选项:
  -ID
        显示 packet ID，不进行合并（默认：合并相同 packet ID 的数据包）

包数量控制:
  -c int
        捕获指定数量的数据包后自动退出
        示例: -c 100

输出文件选项:
  -w string
        将输出内容保存到指定文件
        使用此选项时，终端不会显示抓包内容，且自动禁用颜色输出
        示例: -w output.txt

其他选项:
  -help
        显示详细帮助信息（包含使用示例）
```

#### 常用命令示例

```bash
# 监控所有 TCP 和 UDP 流量
sudo ./target/netbee -proto tcp,udp

# 监控特定主机的 ICMP 流量
sudo ./target/netbee -host 8.8.8.8 -proto icmp

# 监控 HTTP 流量（端口 80）
sudo ./target/netbee -proto tcp -dport 80

# 监控特定来源主机的所有流量
sudo ./target/netbee -shost 192.168.1.100

# 调试数据包丢弃（显示调用栈）
sudo ./target/netbee -kfree

# 组合过滤：监控特定主机到特定端口的 TCP 流量
sudo ./target/netbee -shost 192.168.1.1 -dport 80 -proto tcp

# 捕获 100 个数据包后自动退出
sudo ./target/netbee -c 100

# 将输出保存到文件（自动禁用颜色）
sudo ./target/netbee -w output.txt

# 显示 packet ID，不进行合并（每个事件单独显示）
sudo ./target/netbee -ID
```

#### 命令行参数

**协议过滤**:
- `-proto string`: 过滤协议，逗号分隔（tcp,udp,icmp）

**主机过滤**:
- `-shost string`: 过滤来源主机 IP 地址
- `-dhost string`: 过滤目标主机 IP 地址
- `-host string`: 过滤主机 IP 地址（来源或目标 IP 匹配即可）

**端口过滤**:
- `-sport int`: 过滤来源端口
- `-dport int`: 过滤目的端口
- `-port int`: 过滤端口（来源端口或目的端口匹配即可）

**调试选项**:
- `-kfree`: 显示 kfree_skb 的调用栈信息（用于调试数据包丢弃原因）

**输出选项**:
- `-no-color`: 禁用颜色输出
- `-w string`: 将输出内容保存到指定文件（自动禁用颜色）
- `-c int`: 捕获指定数量的数据包后自动退出
- `-ID`: 显示 packet ID，不进行合并（默认：合并相同 packet ID 的数据包）
- `-help`: 显示详细帮助信息

### 输出说明

#### 输出格式

```
Time                 SrcIP           DstIP           Protocol Length SrcMAC            TTL Info                
----                 -----           -----           -------- ------ ------            --- ----                
11:32:02.628         183.63.127.84   172.26.220.143  TCP      0      ee:ff:ff:ff:ff:ff 51  2079->8888 SYN Seq:449478215 Ack:0 MSS:1456 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:03.598         172.26.220.143  183.63.127.84   TCP      0      b4:ff:ff:00:90:86 64  8888->2079 SYN,ACK Seq:930768552 Ack:449478216 MSS:1460 eth0 [nf_hook_slow->dev_queue_xmit] PID:0
11:32:03.608         183.63.127.84   172.26.220.143  TCP      0      ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 SYN Seq:449478215 Ack:0 MSS:1456 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv] PID:0
11:32:04.086         183.63.127.84   172.26.220.143  TCP      8      ee:ff:ff:ff:ff:ff 51  2079->8888 PSH,ACK Seq:449478216 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow->ip_rcv->ip_local_deliver->nf_hook_slow->ip_rcv->ip_local_deliver->nf_hook_slow->ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv->kfree_skb] PID:1822221=nc(nc -lvkp 8888)
11:32:04.188         172.26.220.143  183.63.127.84   TCP      0      84:24:e8:0d:00:00 64  8888->2079 ACK Seq:930768553 Ack:449478224 eth0 [nf_hook_slow->dev_queue_xmit] PID:0
11:32:04.788         183.63.127.84   172.26.220.143  TCP      12     ee:ff:ff:ff:ff:ff 51  2079->8888 PSH,ACK Seq:449478224 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:04.848         183.63.127.84   172.26.220.143  TCP      12     ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 PSH,ACK Seq:449478224 Ack:930768553  [ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv->kfree_skb] PID:1822221=nc(nc -lvkp 8888)
11:32:04.958         172.26.220.143  183.63.127.84   TCP      0      b4:ff:ff:00:90:86 64  8888->2079 ACK Seq:930768553 Ack:449478236 eth0 [nf_hook_slow->dev_queue_xmit] PID:0
11:32:05.858         183.63.127.84   172.26.220.143  TCP      10     ee:ff:ff:ff:ff:ff 51  2079->8888 PSH,ACK Seq:449478236 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:05.998         183.63.127.84   172.26.220.143  TCP      10     ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 PSH,ACK Seq:449478236 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:06.317         183.63.127.84   172.26.220.143  TCP      10     ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 PSH,ACK Seq:449478236 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:06.768         183.63.127.84   172.26.220.143  TCP      10     ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 PSH,ACK Seq:449478236 Ack:930768553 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:07.346         183.63.127.84   172.26.220.143  TCP      10     ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 PSH,ACK Seq:449478236 Ack:930768553  [ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv->kfree_skb] PID:1822221=nc(nc -lvkp 8888)
11:32:07.447         172.26.220.143  183.63.127.84   TCP      0      20:61:74:20:65:78 64  8888->2079 ACK Seq:930768553 Ack:449478246 eth0 [nf_hook_slow->dev_queue_xmit] PID:0
11:32:24.553         183.63.127.84   172.26.220.143  TCP      0      ee:ff:ff:ff:ff:ff 51  2079->8888 FIN,ACK Seq:449478246 Ack:930768553  [ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv->kfree_skb] PID:1822221=nc(nc -lvkp 8888)
11:32:24.657         172.26.220.143  183.63.127.84   TCP      0      84:24:e8:0d:00:00 64  8888->2079 FIN,ACK Seq:930768553 Ack:449478247 eth0 [nf_hook_slow->dev_queue_xmit] PID:1822221=nc(nc -lvkp 8888)
11:32:24.668         183.63.127.84   172.26.220.143  TCP      0      ee:ff:ff:ff:ff:ff 51  2079->8888 ACK Seq:449478247 Ack:930768554 eth0 [ip_rcv->ip_local_deliver->nf_hook_slow] PID:0 NF:LOCAL_IN:DROP
11:32:26.088         172.26.220.143  183.63.127.84   TCP      0      84:24:e8:0d:00:00 64  [TCP Retransmission] 8888->2079 FIN,ACK Seq:930768553 Ack:449478247 eth0 [nf_hook_slow->dev_queue_xmit] PID:0
11:32:26.116         183.63.127.84   172.26.220.143  TCP      0      ee:ff:ff:ff:ff:ff 51  [TCP Retransmission] 2079->8888 ACK Seq:449478247 Ack:930768554  [ip_rcv->ip_local_deliver->nf_hook_slow->tcp_v4_rcv->kfree_skb] PID:0
```

#### 字段说明

- **Time**: 时间戳
- **SrcIP**: 源 IP 地址
- **DstIP**: 目标 IP 地址
- **Protocol**: 协议类型（TCP、UDP、ICMP）
- **Length**: 数据包长度
- **SrcMAC**: 源 MAC 地址（可能包含厂商名称）
- **TTL**: IP 包的 TTL 值
- **Info**: 详细信息
  - 端口信息（源端口->目标端口）
  - TCP 标志（SYN、ACK、RST 等）
  - Seq 和 Ack 序列号
  - 函数链（数据包经过的内核函数）
  - 进程信息（PID、进程名）
  - Netfilter 信息（钩子点、处理结果）

#### 颜色标记

- **红色**: RST 标志、TCP 重传的 Seq/Ack、NF DROP、`[TCP Retransmission]` 标记
- **黄色**: TTL > 100、MAC 厂商名称


#### 调试技巧

- 使用 `-kfree` 参数查看数据包丢弃的调用栈
- 使用 `-ID` 参数查看每个事件的详细信息
- 使用 `-w` 参数保存输出到文件，便于后续分析

## 许可证

本项目采用 Dual BSD/GPL 许可证。
