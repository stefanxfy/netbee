# NetBee 网络链路排查工具使用说明

## 1. 工具概述

NetBee 是一个基于 eBPF 技术的高性能网络数据包监控和链路排查工具，能够实时监控 Linux 内核网络栈中的数据包处理过程，提供详细的网络流量分析和故障诊断能力。

### 1.1 主要特性

- **实时监控**：实时捕获和显示网络数据包处理过程
- **多协议支持**：支持 TCP、UDP、ICMP 等主流协议
- **灵活过滤**：支持按协议、主机、端口等条件过滤
- **Netfilter 监控**：监控防火墙规则执行过程
- **调用栈分析**：提供详细的调用栈信息用于故障诊断
- **厂商识别**：自动识别网络设备厂商信息

## 2. 安装与运行

### 2.1 系统要求

- Linux 内核版本 4.18 或更高
- 支持 eBPF 的系统
- root 权限（用于加载 eBPF 程序）

### 2.2 运行方式

```bash
# 基本运行（需要 root 权限）
sudo ./target/netbee [选项]

# 示例：监控特定主机的 TCP 流量并启用调用栈分析
sudo ./target/netbee -host 192.168.139.3 -proto tcp -kfree
```

## 3. 命令行参数

### 3.1 协议过滤参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-proto` | 过滤协议，逗号分隔 | `-proto tcp,udp` 或 `-proto icmp` |

### 3.2 主机过滤参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-shost` | 过滤来源主机IP地址 | `-shost 192.168.1.1` |
| `-dhost` | 过滤目标主机IP地址 | `-dhost 8.8.8.8` |
| `-host` | 过滤主机IP地址（来源或目标IP匹配即可） | `-host 10.0.0.1` |

### 3.3 端口过滤参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-sport` | 过滤来源端口 | `-sport 8080` |
| `-dport` | 过滤目的端口 | `-dport 80` |
| `-port` | 过滤端口（来源端口或目的端口匹配即可） | `-port 80` |

### 3.4 调试选项

| 参数 | 说明 | 示例 |
|------|------|------|
| `-kfree` | 显示 kfree_skb 的调用栈信息 | `-kfree` |

### 3.5 帮助选项

| 参数 | 说明 | 示例 |
|------|------|------|
| `-help` | 显示详细帮助信息 | `-help` |

## 4. 使用示例

### 4.1 基础监控示例

```bash
# 监控所有网络流量
sudo ./target/netbee

# 监控所有 TCP 流量
sudo ./target/netbee -proto tcp

# 监控特定主机的所有流量
sudo ./target/netbee -host 192.168.139.3

# 监控 HTTP 流量（端口 80）
sudo ./target/netbee -proto tcp -dport 80

# 监控特定来源主机的所有流量
sudo ./target/netbee -shost 192.168.1.100
```

### 4.2 高级监控示例

```bash
# 监控特定主机到特定端口的 TCP 流量
sudo ./target/netbee -shost 192.168.1.1 -dport 80 -proto tcp

# 监控特定主机的 ICMP 流量
sudo ./target/netbee -host 8.8.8.8 -proto icmp

# 调试数据包丢弃（显示调用栈）
sudo ./target/netbee -kfree

# 组合过滤：监控特定主机到特定端口的流量并启用调用栈分析
sudo ./target/netbee -host 192.168.139.3 -proto tcp -kfree
```

## 5. 输出字段解析

### 5.1 表头说明

| 字段 | 说明 | 示例 |
|------|------|------|
| `Time` | 时间戳 | `15:37:40.003` |
| `SrcIP` | 源 IP 地址 | `192.168.139.3` |
| `DstIP` | 目标 IP 地址 | `192.168.139.50` |
| `Protocol` | 协议类型 | `TCP` |
| `Length` | 数据长度 | `0`（控制包） |
| `SrcMAC` | 源 MAC 地址 | `da:9b:d0:54:e1:02` |
| `TTL` | 生存时间 | `64` |
| `Info` | 详细信息 | 见下文详细说明 |

### 5.2 Info 字段详细解析

Info 字段包含丰富的信息，格式为：
```
[端口信息] [TCP标志] [接口名] [函数名] PID:[进程ID] [调用栈] [Netfilter信息]
```

#### 5.2.1 TCP 连接信息

**SYN 包示例：**
```
443->443 SYN,ECE,CWR eth0 [nf_hook_slow] PID:0 NF:PRE_ROUTING:ACCEPT
```

- `443->443`：源端口->目标端口
- `SYN,ECE,CWR`：TCP 标志位
- `eth0`：网络接口名称
- `[nf_hook_slow]`：触发的内核函数
- `PID:0`：进程ID（0表示内核上下文）
- `NF:PRE_ROUTING:ACCEPT`：Netfilter 钩子点和处理结果

**ACK 包示例：**
```
443->443 ACK eth0 [tcp_v4_rcv] PID:171
```

- `ACK`：TCP 确认标志
- `PID:171`：用户态进程ID

#### 5.2.2 调用栈信息

当使用 `-kfree` 参数时，会显示详细的调用栈：

```
[kfree_skb] PID:0 Stack[__kfree_skb->packet_rcv+0xbc->dev_queue_xmit_nit+0x200->__dev_queue_xmit.cold+0x100->neigh_resolve_output+0xf4->ip_finish_output2+0x310->__ip_finish_output+0x7c->ip_finish_output+0x24->ip_output+0x50->ip_build_and_send_pkt.cold+0xfc->tcp_v4_send_synack.cold+0xc0->tcp_conn_request.cold+0x2f4->tcp_v4_conn_request.cold+0x18->tcp_rcv_state_process.cold+0x98->tcp_v4_do_rcv+0x108->tcp_v4_rcv.cold+0x90]
```

调用栈显示了从 `kfree_skb` 开始的完整调用路径，帮助诊断数据包丢弃的原因。

#### 5.2.3 Netfilter 信息

Netfilter 信息格式：`NF:[钩子点]:[处理结果]`

**钩子点类型：**
- `PRE_ROUTING`：路由前处理
- `LOCAL_IN`：本地输入
- `FORWARD`：转发
- `LOCAL_OUT`：本地输出
- `POST_ROUTING`：路由后处理

**处理结果：**
- `ACCEPT`：接受数据包
- `DROP`：丢弃数据包
- `OTHER`：其他处理结果

## 6. 网络链路知识点解释

### 6.1 Linux 网络栈处理流程

#### 6.1.1 数据包接收流程

```
网卡接收 → netif_rx → nf_hook_slow(PRE_ROUTING) → ip_rcv → 
nf_hook_slow(LOCAL_IN) → ip_local_deliver → tcp_v4_rcv → 应用程序
```

**各阶段说明：**

1. **netif_rx**：网络接口层接收数据包
2. **nf_hook_slow(PRE_ROUTING)**：Netfilter 路由前钩子，进行路由决策前的处理
3. **ip_rcv**：IP 层接收处理，检查 IP 头部
4. **nf_hook_slow(LOCAL_IN)**：Netfilter 本地输入钩子，处理发往本机的数据包
5. **ip_local_deliver**：IP 层本地投递，根据协议类型分发
6. **tcp_v4_rcv**：TCP 层接收处理

#### 6.1.2 数据包发送流程

```
应用程序 → tcp_transmit_skb → ip_queue_xmit → 
nf_hook_slow(LOCAL_OUT) → nf_hook_slow(POST_ROUTING) → dev_queue_xmit → 网卡发送
```

**各阶段说明：**

1. **tcp_transmit_skb**：TCP 层发送处理
2. **ip_queue_xmit**：IP 层队列发送
3. **nf_hook_slow(LOCAL_OUT)**：Netfilter 本地输出钩子
4. **nf_hook_slow(POST_ROUTING)**：Netfilter 路由后钩子
5. **dev_queue_xmit**：设备队列发送

### 6.2 TCP 连接状态跟踪

#### 6.2.1 TCP 三次握手

**第一次握手（SYN）：**
```
客户端 → 服务器：SYN=1, seq=x
```
- 客户端发送 SYN 包请求建立连接
- 在 NetBee 中显示为：`SYN,ECE,CWR` 标志

**第二次握手（SYN+ACK）：**
```
服务器 → 客户端：SYN=1, ACK=1, seq=y, ack=x+1
```
- 服务器确认客户端的 SYN 并发送自己的 SYN
- 在 NetBee 中显示为：`SYN,ACK,ECE` 标志

**第三次握手（ACK）：**
```
客户端 → 服务器：ACK=1, seq=x+1, ack=y+1
```
- 客户端确认服务器的 SYN
- 在 NetBee 中显示为：`ACK` 标志

#### 6.2.2 TCP 连接断开

**四次挥手过程：**

1. **FIN+ACK**：主动关闭方发送 FIN 包
2. **ACK**：被动关闭方确认 FIN
3. **FIN+ACK**：被动关闭方发送 FIN 包
4. **ACK**：主动关闭方确认 FIN

在 NetBee 中显示为：`FIN,ACK` 标志

### 6.3 Netfilter 框架详解

#### 6.3.1 五个钩子点

| 钩子点 | 触发时机 | 主要用途 |
|--------|----------|----------|
| `PRE_ROUTING` | 路由决策前 | 源地址转换、连接跟踪 |
| `LOCAL_IN` | 发往本机前 | 防火墙规则、目标地址转换 |
| `FORWARD` | 转发数据包 | 转发防火墙规则 |
| `LOCAL_OUT` | 本机发出前 | 出站防火墙规则 |
| `POST_ROUTING` | 路由决策后 | 目标地址转换、源地址转换 |

#### 6.3.2 处理结果

- **ACCEPT**：数据包被接受，继续后续处理
- **DROP**：数据包被丢弃，不再处理
- **QUEUE**：数据包被排队到用户空间处理
- **STOLEN**：数据包被"偷走"，由处理函数负责
- **REPEAT**：重新处理数据包

### 6.4 调用栈分析

#### 6.4.1 kfree_skb 调用栈

`kfree_skb` 是内核释放 socket buffer 的函数，其调用栈可以揭示：

1. **数据包丢弃原因**：通过调用栈可以了解数据包在哪个环节被丢弃
2. **内存管理问题**：异常的调用栈可能表明内存泄漏或重复释放
3. **网络栈异常**：调用栈可以显示网络栈处理过程中的异常

#### 6.4.2 常见调用栈模式

**正常释放：**
```
__kfree_skb → consume_skb → 正常处理完成
```

**异常丢弃：**
```
__kfree_skb → kfree_skb_partial → 异常处理路径
```

**内存管理：**
```
__kfree_skb → skb_release_data → 内存释放
```

## 7. 故障诊断指南

### 7.1 连接问题诊断

#### 7.1.1 连接建立失败

**症状：** 只看到 SYN 包，没有 SYN+ACK 响应

**可能原因：**
- 目标主机不可达
- 防火墙阻止连接
- 目标端口未开放

**诊断方法：**
```bash
# 监控特定主机的连接尝试
sudo ./target/netbee -host 目标IP -proto tcp

# 检查 Netfilter 处理结果
# 如果看到 NF:DROP，说明被防火墙阻止
```

#### 7.1.2 连接超时

**症状：** 看到 SYN 包和 SYN+ACK，但没有最终的 ACK

**可能原因：**
- 网络延迟过高
- 中间设备问题
- 应用程序问题

### 7.2 性能问题诊断

#### 7.2.1 数据包丢弃

**症状：** 看到大量的 kfree_skb 调用栈

**诊断方法：**
```bash
# 启用调用栈分析
sudo ./target/netbee -kfree

# 分析调用栈模式，找出丢弃原因
```

#### 7.2.2 网络延迟

**症状：** 数据包处理时间过长

**诊断方法：**
- 观察时间戳间隔
- 分析 Netfilter 处理时间
- 检查调用栈深度

### 7.3 安全分析

#### 7.3.1 异常连接

**监控方法：**
```bash
# 监控特定端口的连接
sudo ./target/netbee -dport 22 -proto tcp

# 监控特定主机的所有连接
sudo ./target/netbee -host 可疑IP
```

#### 7.3.2 防火墙规则验证

**验证方法：**
- 观察 Netfilter 钩子点的处理结果
- 确认防火墙规则是否按预期工作
- 分析被 DROP 的数据包特征

## 8. 最佳实践

### 8.1 监控策略

1. **按需监控**：根据具体需求选择合适的过滤条件
2. **性能考虑**：避免监控所有流量，使用过滤条件减少性能影响
3. **日志记录**：重要监控结果应保存到文件

### 8.2 故障排查流程

1. **确定问题范围**：使用过滤条件缩小问题范围
2. **启用详细分析**：使用 `-kfree` 参数获取调用栈信息
3. **分析数据流**：观察数据包在网络栈中的完整处理过程
4. **定位问题点**：通过调用栈和 Netfilter 信息定位问题

### 8.3 性能优化

1. **合理使用过滤**：避免过于宽泛的监控条件
2. **监控时间控制**：避免长时间连续监控
3. **资源管理**：注意内存和 CPU 使用情况

## 9. 常见问题解答

### 9.1 权限问题

**Q: 为什么需要 root 权限？**
A: eBPF 程序需要在内核态运行，加载 eBPF 程序需要 root 权限。

### 9.2 性能影响

**Q: 监控会影响网络性能吗？**
A: NetBee 使用 eBPF 技术，性能影响很小，但仍建议在生产环境中谨慎使用。

### 9.3 兼容性

**Q: 支持哪些 Linux 发行版？**
A: 支持内核版本 4.18+ 的 Linux 发行版，包括 CentOS、Ubuntu、Debian 等。

### 9.4 数据解读

**Q: 如何理解调用栈信息？**
A: 调用栈显示了函数调用的完整路径，从最底层的内核函数到具体的处理函数，帮助理解数据包的处理过程。

## 10. 总结

NetBee 是一个功能强大的网络链路排查工具，通过实时监控网络数据包的处理过程，为网络故障诊断、性能分析和安全监控提供了强有力的支持。掌握其使用方法和网络知识，能够有效提升网络运维和故障排查的效率。

在使用过程中，建议：
- 充分理解 Linux 网络栈的工作原理
- 合理使用过滤条件提高监控效率
- 结合调用栈分析进行深度故障诊断
- 注意工具的性能影响和系统资源使用
