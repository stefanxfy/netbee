# SEC("socket") 网络信息获取能力详解

## 概述

`SEC("socket")` 类型的eBPF程序可以获取完整的网络数据包信息，包括MAC地址、IP地址、端口等。通过 `struct __sk_buff *skb` 参数，可以访问数据包的各个层次。

## 可获取的网络信息

### 1. MAC地址信息

```c
SEC("socket")
int network_trace(struct __sk_buff *skb) {
    struct ethhdr eth;
    
    // 读取以太网头部，获取MAC地址
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    
    // 源MAC地址
    __u8 src_mac[6];
    __builtin_memcpy(src_mac, eth.h_source, 6);
    
    // 目标MAC地址  
    __u8 dst_mac[6];
    __builtin_memcpy(dst_mac, eth.h_dest, 6);
    
    // 协议类型
    __u16 protocol = bpf_ntohs(eth.h_proto);
    
    return 0;
}
```

### 2. IP地址信息

```c
SEC("socket")
int network_trace(struct __sk_buff *skb) {
    struct iphdr iph;
    
    // 读取IP头部（跳过以太网头部14字节）
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    
    // 源IP地址
    __u32 src_ip = bpf_ntohl(iph.saddr);
    
    // 目标IP地址
    __u32 dst_ip = bpf_ntohl(iph.daddr);
    
    // IP协议类型
    __u8 protocol = iph.protocol;
    
    // TTL值
    __u8 ttl = iph.ttl;
    
    // IP头部长度
    __u8 ihl = iph.ihl;
    
    // 总长度
    __u16 total_len = bpf_ntohs(iph.tot_len);
    
    return 0;
}
```

### 3. 端口信息

```c
SEC("socket")
int network_trace(struct __sk_buff *skb) {
    struct iphdr iph;
    struct tcphdr tcph;
    struct udphdr udph;
    
    // 读取IP头部
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    
    // 计算传输层头部偏移
    __u32 transport_offset = ETH_HLEN + (iph.ihl * 4);
    
    if (iph.protocol == IPPROTO_TCP) {
        // TCP端口信息
        bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph));
        
        __u16 src_port = bpf_ntohs(tcph.source);
        __u16 dst_port = bpf_ntohs(tcph.dest);
        
        // TCP标志位
        __u8 tcp_flags = tcph.fin | (tcph.syn << 1) | (tcph.rst << 2) | 
                        (tcph.psh << 3) | (tcph.ack << 4) | (tcph.urg << 5);
        
        // TCP序列号和确认号
        __u32 seq = bpf_ntohl(tcph.seq);
        __u32 ack_seq = bpf_ntohl(tcph.ack_seq);
        
    } else if (iph.protocol == IPPROTO_UDP) {
        // UDP端口信息
        bpf_skb_load_bytes(skb, transport_offset, &udph, sizeof(udph));
        
        __u16 src_port = bpf_ntohs(udph.source);
        __u16 dst_port = bpf_ntohs(udph.dest);
        
        // UDP长度
        __u16 udp_len = bpf_ntohs(udph.len);
    }
    
    return 0;
}
```

### 4. 应用层数据

```c
SEC("socket")
int http_trace(struct __sk_buff *skb) {
    struct iphdr iph;
    struct tcphdr tcph;
    
    // 读取IP和TCP头部
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4), &tcph, sizeof(tcph));
    
    // 计算应用层数据偏移
    __u32 app_offset = ETH_HLEN + (iph.ihl * 4) + (tcph.doff * 4);
    
    // 计算应用层数据长度
    __u32 app_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4) - (tcph.doff * 4);
    
    // 读取HTTP数据
    char http_data[1024];
    if (app_len > 0 && app_len <= sizeof(http_data)) {
        bpf_skb_load_bytes(skb, app_offset, http_data, app_len);
        
        // 解析HTTP请求方法
        if (bpf_strncmp(http_data, 3, "GET") == 0) {
            // 处理GET请求
        } else if (bpf_strncmp(http_data, 4, "POST") == 0) {
            // 处理POST请求
        }
    }
    
    return 0;
}
```

## 完整的网络信息获取示例

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800

// 事件结构体
struct network_event {
    // MAC地址
    __u8 src_mac[6];
    __u8 dst_mac[6];
    
    // IP信息
    __u32 src_ip;
    __u32 dst_ip;
    __u8 ip_proto;
    __u8 ttl;
    
    // 端口信息
    __u16 src_port;
    __u16 dst_port;
    
    // TCP信息
    __u8 tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    
    // 数据长度
    __u16 data_len;
    
    // 时间戳
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("socket")
int network_monitor(struct __sk_buff *skb) {
    struct network_event *event;
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcph;
    
    // 分配事件结构
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // 获取时间戳
    event->timestamp = bpf_ktime_get_ns();
    
    // 读取以太网头部
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    
    // 检查是否为IP协议
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // 复制MAC地址
    __builtin_memcpy(event->src_mac, eth.h_source, 6);
    __builtin_memcpy(event->dst_mac, eth.h_dest, 6);
    
    // 读取IP头部
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    
    // 填充IP信息
    event->src_ip = bpf_ntohl(iph.saddr);
    event->dst_ip = bpf_ntohl(iph.daddr);
    event->ip_proto = iph.protocol;
    event->ttl = iph.ttl;
    
    // 只处理TCP协议
    if (iph.protocol == IPPROTO_TCP) {
        // 读取TCP头部
        bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4), &tcph, sizeof(tcph));
        
        // 填充TCP信息
        event->src_port = bpf_ntohs(tcph.source);
        event->dst_port = bpf_ntohs(tcph.dest);
        event->tcp_flags = tcph.fin | (tcph.syn << 1) | (tcph.rst << 2) | 
                          (tcph.psh << 3) | (tcph.ack << 4) | (tcph.urg << 5);
        event->tcp_seq = bpf_ntohl(tcph.seq);
        event->tcp_ack = bpf_ntohl(tcph.ack_seq);
        
        // 计算数据长度
        event->data_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4) - (tcph.doff * 4);
    }
    
    // 提交事件
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
```

## 与现有代码的对比

### 现有http_trace.bpf.c中的实现

```c
// 获取IP地址
bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &event->saddr, 4);
bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &event->daddr, 4);

// 获取端口
event->sport = bpf_ntohs(tcph.source);
event->dport = bpf_ntohs(tcph.dest);
```

### 可以扩展获取的信息

```c
// 获取MAC地址（现有代码未实现）
struct ethhdr eth;
bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
__builtin_memcpy(event->src_mac, eth.h_source, 6);
__builtin_memcpy(event->dst_mac, eth.h_dest, 6);

// 获取更多TCP信息
event->tcp_flags = tcph.fin | (tcph.syn << 1) | (tcph.rst << 2) | 
                  (tcph.psh << 3) | (tcph.ack << 4) | (tcph.urg << 5);
event->tcp_seq = bpf_ntohl(tcph.seq);
event->tcp_ack = bpf_ntohl(tcph.ack_seq);

// 获取TTL
event->ttl = iph.ttl;
```

## 总结

`SEC("socket")` 可以获取：

✅ **MAC地址**：源MAC、目标MAC  
✅ **IP地址**：源IP、目标IP、协议类型、TTL  
✅ **端口信息**：源端口、目标端口  
✅ **TCP信息**：标志位、序列号、确认号  
✅ **UDP信息**：长度字段  
✅ **应用层数据**：HTTP、HTTPS等协议内容  
✅ **时间戳**：数据包时间戳  

**限制：**
❌ 无法直接获取进程信息（PID、进程名）  
❌ 无法获取系统调用参数  
❌ 无法获取用户态上下文信息  

因此，`SEC("socket")` 非常适合网络协议分析，但需要结合其他类型的eBPF程序（如kprobe、uprobe）来获取完整的应用上下文信息。
