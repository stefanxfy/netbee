# HTTP/HTTPS 监控系统设计文档

## 1. 概述

本文档详细描述了在现有网络监控系统基础上，新增HTTP/HTTPS协议监控功能的设计方案。该功能将监控HTTP/HTTPS请求和响应，包括协议版本、请求方法、URI、状态码、响应时长、响应体内容等关键信息。

## 2. 系统架构

### 2.1 整体架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   eBPF Kernel   │    │   User Space    │    │   Output        │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Socket Hook │ │    │ │ HTTP Monitor│ │    │ │ HTTP Events │ │
│ │ TLS Hook    │ │───▶│ │ Thread      │ │───▶│ │ Display     │ │
│ │ SSL Hook    │ │    │ │             │ │    │ │             │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2.2 独立实现架构

HTTP/HTTPS监控采用完全独立的实现，与现有的网络监控系统并行运行：

```
┌─────────────────────────────────────────────────────────────┐
│                    独立HTTP/HTTPS监控系统                    │
├─────────────────────────────────────────────────────────────┤
│  eBPF程序: netbee-http.ebpf.c                              │
│  ├── Socket Filter: 监控HTTP/HTTPS数据包                    │
│  ├── TLS Hook: 监控TLS握手过程                             │
│  └── SSL Hook: 监控SSL读写操作                             │
├─────────────────────────────────────────────────────────────┤
│  用户态程序: main-http.go                                  │
│  ├── HTTP事件处理线程                                       │
│  ├── 过滤配置管理                                           │
│  └── 格式化输出                                             │
├─────────────────────────────────────────────────────────────┤
│  运行命令: ./target/netbee-http                           │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 组件关系

- **独立eBPF程序**：`netbee-http.ebpf.c`专门处理HTTP/HTTPS监控
- **独立用户态程序**：`main-http.go`专门处理HTTP/HTTPS事件
- **独立输出格式**：专门针对HTTP/HTTPS优化的输出格式
- **完全独立运行**：与现有`netbee.ebpf.c`和`main.go`完全分离

## 3. 事件结构设计

### 3.1 HTTP/HTTPS事件结构体

基于现有的`so_event`结构，新增`http_event`结构体：

```c
// HTTP/HTTPS事件结构
struct http_event {
    // 继承so_event的基础网络信息
    __u32 src_addr;
    __u32 dst_addr;
    __u32 ip_proto;
    __u8 src_mac[6];
    __u8 dst_mac[6];
    __u8 ttl;
    __u32 ifindex;
    __u16 src_port;     // 源端口
    __u16 dst_port;     // 目标端口
    // TCP相关字段
    __u8 tcp_flags;     // TCP标志位
    __u32 tcp_seq;      // TCP序列号
    __u32 tcp_ack;      // TCP确认号
    __u16 tcp_len;      // TCP数据长度
    // UDP相关字段
    __u16 udp_len;      // UDP数据长度
    char func_name[FUNCNAME_MAX_LEN];  // 函数名
    
    // HTTP/HTTPS特有字段
    __u8 http_version;      // HTTP版本 (1=HTTP/1.0, 2=HTTP/1.1, 3=HTTP/2.0)
    char method[16];        // HTTP请求方法 (GET, POST, PUT, DELETE等)
    char request_uri[256];  // 请求URI路径
    char request_params[512]; // 请求参数 (GET查询参数或POST表单数据)
    __u16 status_code;      // HTTP响应状态码
    __u16 body_len;         // 响应体长度
    char response_body[1024]; // 响应体内容(截断到1024字节)
    
    // HTTPS特有字段
    __u8 tls_handshake_result; // TLS握手结果 (0=失败, 1=成功)
    __u8 rw;                // 读写标识 (0=read, 1=write)
    
    // 时间戳
    __u64 timestamp_ns;     // 事件时间戳(纳秒)
};
```

### 3.2 事件类型定义

```c
// HTTP版本枚举
#define HTTP_VERSION_1_0    1
#define HTTP_VERSION_1_1    2
#define HTTP_VERSION_2_0    3

// TLS握手结果
#define TLS_HANDSHAKE_FAIL  0
#define TLS_HANDSHAKE_SUCCESS 1

// 事件类型
#define HTTP_EVENT_REQUEST  1
#define HTTP_EVENT_RESPONSE 2
#define HTTPS_EVENT_REQUEST 3
#define HTTPS_EVENT_RESPONSE 4

// 读写标识
#define SSL_READ  0
#define SSL_WRITE 1

// 缓冲区大小定义
#define MAX_BODY_LENGTH     1024
#define MAX_URI_LENGTH      256
#define MAX_PARAMS_LENGTH   512
#define MAX_METHOD_LENGTH   16
#define FUNCNAME_MAX_LEN    32

// HTTP方法说明
/*
 * 标准HTTP方法：
 * GET     - 获取资源
 * POST    - 提交数据
 * PUT     - 更新资源
 * DELETE  - 删除资源
 * HEAD    - 获取资源头部信息
 * OPTIONS - 获取服务器支持的HTTP方法
 * PATCH   - 部分更新资源
 * TRACE   - 回显服务器收到的请求
 * CONNECT - 建立隧道连接（用于代理）
 */
```

## 4. eBPF Hook点设计

### 4.0 技术选择说明

本设计选择使用`SEC("socket")` socket filter而不是系统调用监控的原因：

1. **性能优势**：Socket filter直接在内核网络栈中处理数据包，性能最优
2. **数据完整性**：可以直接访问完整的网络数据包内容，包括MAC地址、IP、端口、协议数据
3. **简化设计**：不需要复杂的进程上下文管理，专注于网络协议分析
4. **安全性**：只访问网络数据包，不涉及进程信息，降低安全风险
5. **兼容性**：适用于各种网络应用，不依赖特定的系统调用模式
6. **协议识别**：通过协议内容而非端口号识别HTTP/HTTPS流量，支持任意端口的HTTP服务

### 4.0.1 端口过滤策略说明

**为什么去掉端口过滤：**

1. **非标准端口HTTP服务**：
   - 开发环境：`http://localhost:3000`, `http://localhost:8080`
   - 微服务：`http://api-service:9000`, `http://user-service:8001`
   - 容器化应用：`http://app:5000`, `http://web:3001`

2. **HTTPS over 非标准端口**：
   - 内网HTTPS：`https://internal-api:8443`
   - 开发HTTPS：`https://localhost:9443`
   - 代理服务：`https://proxy:8080`

3. **协议内容识别更准确**：
   - 端口80/443上可能运行非HTTP服务
   - 通过HTTP方法/响应行识别更可靠
   - 支持HTTP隧道和代理场景

**新的识别策略：**
```c
// 旧方式：基于端口过滤
if (port != 80 && port != 443) return 0;

// 新方式：基于协议内容识别
if (bpf_strncmp(data, 3, "GET") == 0 ||     // HTTP请求
    bpf_strncmp(data, 4, "HTTP") == 0) {    // HTTP响应
    // 这是HTTP流量
}
```

## 4.1 eBPF Hook点设计

### 4.2 HTTP监控Hook点

#### 4.2.1 Socket Filter监控
```c
// HTTP/HTTPS事件ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events SEC(".maps");

// HTTP过滤配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 20);
} http_filter_config SEC(".maps");

// 使用socket filter直接监控HTTP数据包
SEC("socket")
int handle_http_traffic(struct __sk_buff *skb) {
    struct http_event *event;
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcph;
    
    // 读取以太网头部
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP) {
        return 0;
    }
    
    // 读取IP头部
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    if (iph.protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // 读取TCP头部
    bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4), &tcph, sizeof(tcph));
    
    // 获取端口信息（用于记录，不用于过滤）
    __u16 src_port = bpf_ntohs(tcph.source);
    __u16 dst_port = bpf_ntohs(tcph.dest);
    
    // 计算应用层数据偏移和长度
    __u32 app_offset = ETH_HLEN + (iph.ihl * 4) + (tcph.doff * 4);
    __u32 app_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4) - (tcph.doff * 4);
    
    if (app_len < 7) {
        return 0;
    }
    
    // 通过协议内容识别HTTP/HTTPS流量（不依赖端口）
    char start_buffer[10] = { };  // 增加缓冲区大小以支持更长的HTTP方法
    bpf_skb_load_bytes(skb, app_offset, start_buffer, 10);
    if (bpf_strncmp(start_buffer, 3, "GET") != 0 &&           // GET
        bpf_strncmp(start_buffer, 4, "POST") != 0 &&          // POST
        bpf_strncmp(start_buffer, 3, "PUT") != 0 &&           // PUT
        bpf_strncmp(start_buffer, 6, "DELETE") != 0 &&        // DELETE
        bpf_strncmp(start_buffer, 4, "HEAD") != 0 &&          // HEAD
        bpf_strncmp(start_buffer, 7, "OPTIONS") != 0 &&       // OPTIONS
        bpf_strncmp(start_buffer, 5, "PATCH") != 0 &&         // PATCH
        bpf_strncmp(start_buffer, 5, "TRACE") != 0 &&         // TRACE
        bpf_strncmp(start_buffer, 7, "CONNECT") != 0 &&       // CONNECT
        bpf_strncmp(start_buffer, 4, "HTTP") != 0) {          // HTTP响应
        return 0;  // 不是HTTP协议，过滤掉
    }
    
    // 分配事件结构
    event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // 填充基础网络信息
    event->src_addr = bpf_ntohl(iph.saddr);
    event->dst_addr = bpf_ntohl(iph.daddr);
    event->ip_proto = iph.protocol;
    event->ttl = iph.ttl;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->tcp_flags = tcph.fin | (tcph.syn << 1) | (tcph.rst << 2) | 
                      (tcph.psh << 3) | (tcph.ack << 4) | (tcph.urg << 5);
    event->tcp_seq = bpf_ntohl(tcph.seq);
    event->tcp_ack = bpf_ntohl(tcph.ack_seq);
    event->tcp_len = app_len;
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // 复制MAC地址
    __builtin_memcpy(event->src_mac, eth.h_source, 6);
    __builtin_memcpy(event->dst_mac, eth.h_dest, 6);
    
    // 读取HTTP数据
    if (app_len > 0 && app_len <= sizeof(event->response_body)) {
        bpf_skb_load_bytes(skb, app_offset, event->response_body, app_len);
        event->body_len = app_len;
        
    // 解析HTTP协议
    if (parse_http_request(event->response_body, app_len, event) == 0 ||
        parse_http_response(event->response_body, app_len, event) == 0) {
        
        // 应用HTTP过滤
        if (apply_http_filters(event) == 0) {
            bpf_ringbuf_submit(event, 0);
        } else {
            bpf_ringbuf_discard(event, 0);
        }
    } else {
        bpf_ringbuf_discard(event, 0);
    }
    } else {
        bpf_ringbuf_discard(event, 0);
    }
    
    return 0;
}
```

### 4.3 HTTPS监控Hook点

#### 4.3.1 TLS握手监控
```c
// TLS握手状态存储
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} tls_handshake_start SEC(".maps");

// TLS握手入口处理
SEC("uprobe/do_handshake")
int handle_tls_handshake_entry(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 start_time = bpf_ktime_get_ns();
    
    // 记录握手开始时间
    bpf_map_update_elem(&tls_handshake_start, &tid, &start_time, BPF_ANY);
    
    return 0;
}

// TLS握手退出处理
SEC("uretprobe/do_handshake")
int handle_tls_handshake_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 end_time = bpf_ktime_get_ns();
    
    // 获取握手开始时间
    __u64 *start_time = bpf_map_lookup_elem(&tls_handshake_start, &tid);
    if (!start_time) {
        return 0;
    }
    
    // 获取握手结果
    int result = PT_REGS_RC(ctx);
    __u8 handshake_result = (result == 0) ? TLS_HANDSHAKE_SUCCESS : TLS_HANDSHAKE_FAIL;
    
    // 创建HTTPS事件记录握手信息
    struct http_event *event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
    if (event) {
        event->tls_handshake_result = handshake_result;
        event->timestamp_ns = end_time;
        bpf_ringbuf_submit(event, 0);
    }
    
    // 清理状态
    bpf_map_delete_elem(&tls_handshake_start, &tid);
    
    return 0;
}
```

#### 4.3.2 SSL读写监控
```c
// 用于存储SSL读写缓冲区的哈希映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} ssl_bufs SEC(".maps");

// 用于存储大量数据的缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct http_event);
    __uint(max_entries, 1);
} ssl_data_buffer SEC(".maps");

// SSL读写入口处理
static int ssl_rw_entry(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    // 存储缓冲区地址到哈希映射
    bpf_map_update_elem(&ssl_bufs, &tid, (__u64 *)&buf, BPF_ANY);
    return 0;
}

// SSL读写退出处理
static int ssl_rw_exit(struct pt_regs *ctx, int rw) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    // 从哈希映射中读取SSL读写缓冲区的地址
    __u64 *bufp = bpf_map_lookup_elem(&ssl_bufs, &tid);
    if (!bufp) {
        return 0;
    }
    
    // 从寄存器中读取函数调用的返回值
    int len = PT_REGS_RC(ctx);
    if (len <= 0) {
        return 0;
    }
    
    // 分配数据缓冲区
    __u32 zero = 0;
    struct http_event *event = bpf_map_lookup_elem(&ssl_data_buffer, &zero);
    if (!event) {
        return 0;
    }
    
    // 填充事件信息
    event->rw = rw;  // 0: read, 1: write
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // 读取SSL读写缓冲区的数据
    event->body_len = (size_t)MAX_BODY_LENGTH < (size_t)len ? 
                      (size_t)MAX_BODY_LENGTH : (size_t)len;
    
    if (bufp != NULL) {
        bpf_probe_read_user(event->response_body, event->body_len, (const char *)*bufp);
    }
    
    // 解析HTTPS数据中的HTTP协议
    if (parse_https_data(event->response_body, event->body_len, event) == 0) {
        // 提交到HTTP事件ring buffer
        bpf_ringbuf_submit(event, 0);
    }
    
    // 清理哈希映射
    bpf_map_delete_elem(&ssl_bufs, &tid);
    return 0;
}

// SSL写操作监控
SEC("uprobe/SSL_write")
int handle_ssl_write_entry(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    return ssl_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_write")
int handle_ssl_write_exit(struct pt_regs *ctx) {
    return ssl_rw_exit(ctx, 1);  // 1: write
}

// SSL读操作监控
SEC("uprobe/SSL_read")
int handle_ssl_read_entry(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    return ssl_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_read")
int handle_ssl_read_exit(struct pt_regs *ctx) {
    return ssl_rw_exit(ctx, 0);  // 0: read
}
```

### 4.4 HTTP过滤逻辑

#### 4.4.1 HTTP过滤函数
```c
// HTTP过滤函数
static int apply_http_filters(struct http_event *event) {
    // 检查HTTP方法过滤
    __u32 method_key = 11;
    __u32 *method_filter = bpf_map_lookup_elem(&http_filter_config, &method_key);
    if (method_filter && *method_filter != 0) {
        __u32 event_method = string_to_http_method(event->method);
        if (event_method != *method_filter) {
            return -1;  // 过滤掉
        }
    }
    
    // 检查HTTP状态码过滤
    __u32 status_key = 12;
    __u32 *status_filter = bpf_map_lookup_elem(&http_filter_config, &status_key);
    if (status_filter && *status_filter != 0) {
        if (event->status_code != *status_filter) {
            return -1;  // 过滤掉
        }
    }
    
    // 检查HTTP URI过滤
    __u32 uri_key = 13;
    __u32 *uri_filter = bpf_map_lookup_elem(&http_filter_config, &uri_key);
    if (uri_filter && *uri_filter != 0) {
        __u32 uri_hash = hash_string(event->request_uri);
        if (uri_hash != *uri_filter) {
            return -1;  // 过滤掉
        }
    }
    
    return 0;  // 通过过滤
}

// HTTP方法字符串转数字
static __u32 string_to_http_method(const char *method) {
    if (bpf_strncmp(method, 3, "GET") == 0) return 1;
    if (bpf_strncmp(method, 4, "POST") == 0) return 2;
    if (bpf_strncmp(method, 3, "PUT") == 0) return 3;
    if (bpf_strncmp(method, 6, "DELETE") == 0) return 4;
    if (bpf_strncmp(method, 4, "HEAD") == 0) return 5;
    if (bpf_strncmp(method, 7, "OPTIONS") == 0) return 6;
    if (bpf_strncmp(method, 5, "PATCH") == 0) return 7;
    if (bpf_strncmp(method, 5, "TRACE") == 0) return 8;
    if (bpf_strncmp(method, 7, "CONNECT") == 0) return 9;
    return 0;
}

// 字符串哈希函数
static __u32 hash_string(const char *str) {
    __u32 hash = 0;
    for (int i = 0; i < 256 && str[i] != '\0'; i++) {
        hash = hash * 31 + str[i];
    }
    return hash;
}
```

### 4.5 HTTP/HTTPS数据解析

#### 4.5.1 HTTP请求解析
```c
// 解析HTTP请求行
static int parse_http_request(const char *data, size_t len, struct http_event *event) {
    // 解析 "METHOD URI HTTP/VERSION"
    // 提取方法、URI、版本信息
    // 解析URI中的查询参数
    // 填充request_params字段
}

// 解析HTTP响应行
static int parse_http_response(const char *data, size_t len, struct http_event *event) {
    // 解析 "HTTP/VERSION STATUS_CODE REASON_PHRASE"
    // 提取状态码信息
}

// 解析HTTP请求参数
static int parse_http_params(const char *uri, size_t uri_len, struct http_event *event) {
    // 解析GET查询参数 (如: ?key1=value1&key2=value2)
    // 解析POST表单数据 (如: key1=value1&key2=value2)
    // 敏感信息脱敏处理
    // 格式化为JSON格式存储到request_params
}
```

#### 4.4.2 HTTP头部解析
```c
// 解析HTTP头部
static int parse_http_headers(const char *data, size_t len, struct http_event *event) {
    // 解析Content-Length、Content-Type等头部
    // 确定响应体长度
}
```

#### 4.4.3 HTTPS数据解析
```c
// 解析HTTPS数据中的HTTP协议
static int parse_https_data(const char *data, size_t len, struct http_event *event) {
    if (len < 7) {
        return -1;  // 数据太短
    }
    
    // 检查是否是HTTP请求
    if (bpf_strncmp(data, 3, "GET") == 0 ||
        bpf_strncmp(data, 4, "POST") == 0 ||
        bpf_strncmp(data, 3, "PUT") == 0 ||
        bpf_strncmp(data, 6, "DELETE") == 0 ||
        bpf_strncmp(data, 4, "HEAD") == 0 ||
        bpf_strncmp(data, 7, "OPTIONS") == 0 ||
        bpf_strncmp(data, 5, "PATCH") == 0 ||
        bpf_strncmp(data, 5, "TRACE") == 0 ||
        bpf_strncmp(data, 7, "CONNECT") == 0) {
        
        // 解析HTTP请求
        return parse_http_request(data, len, event);
    }
    // 检查是否是HTTP响应
    else if (bpf_strncmp(data, 4, "HTTP") == 0) {
        // 解析HTTP响应
        return parse_http_response(data, len, event);
    }
    
    return -1;  // 不是HTTP协议
}

// 从SSL数据中提取HTTP信息
static int extract_http_from_ssl(const char *ssl_data, size_t ssl_len, struct http_event *event) {
    // 查找HTTP协议标识
    for (size_t i = 0; i < ssl_len - 7; i++) {
        if (bpf_strncmp(ssl_data + i, 3, "GET") == 0 ||
            bpf_strncmp(ssl_data + i, 4, "POST") == 0 ||
            bpf_strncmp(ssl_data + i, 3, "PUT") == 0 ||
            bpf_strncmp(ssl_data + i, 6, "DELETE") == 0 ||
            bpf_strncmp(ssl_data + i, 4, "HEAD") == 0 ||
            bpf_strncmp(ssl_data + i, 7, "OPTIONS") == 0 ||
            bpf_strncmp(ssl_data + i, 5, "PATCH") == 0 ||
            bpf_strncmp(ssl_data + i, 5, "TRACE") == 0 ||
            bpf_strncmp(ssl_data + i, 7, "CONNECT") == 0 ||
            bpf_strncmp(ssl_data + i, 4, "HTTP") == 0) {
            
            // 找到HTTP数据，进行解析
            return parse_https_data(ssl_data + i, ssl_len - i, event);
        }
    }
    
    return -1;  // 未找到HTTP数据
}
```

## 5. 用户态过滤参数设计

### 5.1 新增命令行参数

```go
// 在main-http.go中新增参数
var (
    // HTTP/HTTPS body解析开关
    parseBody = flag.Bool("body", false, "解析HTTP/HTTPS响应体内容")
    
    // HTTP/HTTPS特定过滤
    httpMethod = flag.String("method", "", "过滤HTTP请求方法 (例如: GET,POST)")
    httpStatus = flag.Int("status", 0, "过滤HTTP状态码 (例如: 200,404)")
    httpUri    = flag.String("uri", "", "过滤HTTP URI模式 (例如: /api/*)")
)
```

### 5.2 过滤配置扩展

```go
// 独立HTTP过滤配置结构
type HTTPFilterConfig struct {
    // 网络层过滤字段
    SrcHost   uint32
    DstHost   uint32
    Host      uint32
    DstPort   uint16
    SrcPort   uint16
    Port      uint16
    
    // HTTP/HTTPS过滤字段
    ParseBody    bool      // 是否解析响应体
    HTTPMethod   string    // HTTP方法过滤
    HTTPStatus   uint16    // HTTP状态码过滤
    HTTPUri      string    // HTTP URI过滤
}
```

### 5.3 过滤配置解析函数

```go
// 独立HTTP过滤配置解析函数
func ParseHTTPFilterConfig(srcHostStr, dstHostStr, hostStr string, 
                          dstPort, srcPort, port int,
                          httpMethod string, httpStatus int, httpUri string) (*HTTPFilterConfig, error) {
    config := &HTTPFilterConfig{}
    
    // 解析网络层过滤
    if srcHostStr != "" {
        ip := net.ParseIP(srcHostStr)
        if ip == nil {
            return nil, fmt.Errorf("无效的来源主机地址: %s", srcHostStr)
        }
        ipv4 := ip.To4()
        if ipv4 == nil {
            return nil, fmt.Errorf("只支持IPv4地址: %s", srcHostStr)
        }
        config.SrcHost = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
    }
    
    if dstHostStr != "" {
        ip := net.ParseIP(dstHostStr)
        if ip == nil {
            return nil, fmt.Errorf("无效的目标主机地址: %s", dstHostStr)
        }
        ipv4 := ip.To4()
        if ipv4 == nil {
            return nil, fmt.Errorf("只支持IPv4地址: %s", dstHostStr)
        }
        config.DstHost = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
    }
    
    if hostStr != "" {
        ip := net.ParseIP(hostStr)
        if ip == nil {
            return nil, fmt.Errorf("无效的主机地址: %s", hostStr)
        }
        ipv4 := ip.To4()
        if ipv4 == nil {
            return nil, fmt.Errorf("只支持IPv4地址: %s", hostStr)
        }
        config.Host = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
    }
    
    config.DstPort = uint16(dstPort)
    config.SrcPort = uint16(srcPort)
    config.Port = uint16(port)
    
    // 解析HTTP方法过滤
    if httpMethod != "" {
        httpMethod = strings.ToUpper(strings.TrimSpace(httpMethod))
        validMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
        valid := false
        for _, method := range validMethods {
            if httpMethod == method {
                valid = true
                break
            }
        }
        if !valid {
            return nil, fmt.Errorf("不支持的HTTP方法: %s", httpMethod)
        }
        config.HTTPMethod = httpMethod
    }
    
    // 解析HTTP状态码过滤
    if httpStatus < 0 || httpStatus > 599 {
        return nil, fmt.Errorf("无效的HTTP状态码: %d", httpStatus)
    }
    config.HTTPStatus = uint16(httpStatus)
    
    // 解析HTTP URI过滤
    if httpUri != "" {
        config.HTTPUri = strings.TrimSpace(httpUri)
        // 支持通配符匹配，如 /api/*, /user/*/profile
    }
    
    return config, nil
}
```

### 5.4 eBPF过滤配置

```go
// 独立HTTP过滤配置设置函数
func SetHTTPFilterConfig(coll *ebpf.Collection, config *HTTPFilterConfig) error {
    // 设置网络层过滤
    filterMap := coll.Maps["filter_config"]
    if filterMap != nil {
        // 设置来源主机过滤 (key=0)
        if config.SrcHost != 0 {
            key := uint32(0)
            if err := filterMap.Put(key, config.SrcHost); err != nil {
                return fmt.Errorf("设置来源主机过滤失败: %v", err)
            }
        }
        
        // 设置目标主机过滤 (key=5)
        if config.DstHost != 0 {
            key := uint32(5)
            if err := filterMap.Put(key, config.DstHost); err != nil {
                return fmt.Errorf("设置目标主机过滤失败: %v", err)
            }
        }
        
        // 设置主机过滤 (key=6)
        if config.Host != 0 {
            key := uint32(6)
            if err := filterMap.Put(key, config.Host); err != nil {
                return fmt.Errorf("设置主机过滤失败: %v", err)
            }
        }
        
        // 设置目的端口过滤 (key=2)
        if config.DstPort != 0 {
            key := uint32(2)
            if err := filterMap.Put(key, uint32(config.DstPort)); err != nil {
                return fmt.Errorf("设置目的端口过滤失败: %v", err)
            }
        }
        
        // 设置来源端口过滤 (key=3)
        if config.SrcPort != 0 {
            key := uint32(3)
            if err := filterMap.Put(key, uint32(config.SrcPort)); err != nil {
                return fmt.Errorf("设置来源端口过滤失败: %v", err)
            }
        }
        
        // 设置端口过滤 (key=4)
        if config.Port != 0 {
            key := uint32(4)
            if err := filterMap.Put(key, uint32(config.Port)); err != nil {
                return fmt.Errorf("设置端口过滤失败: %v", err)
            }
        }
    }
    
    // 设置HTTP层过滤
    httpFilterMap := coll.Maps["http_filter_config"]
    if httpFilterMap != nil {
        // 设置HTTP方法过滤 (key=11)
        if config.HTTPMethod != "" {
            key := uint32(11)
            value := stringToHTTPMethod(config.HTTPMethod)
            if err := httpFilterMap.Put(key, value); err != nil {
                return fmt.Errorf("设置HTTP方法过滤失败: %v", err)
            }
        }
        
        // 设置HTTP状态码过滤 (key=12)
        if config.HTTPStatus != 0 {
            key := uint32(12)
            if err := httpFilterMap.Put(key, uint32(config.HTTPStatus)); err != nil {
                return fmt.Errorf("设置HTTP状态码过滤失败: %v", err)
            }
        }
        
        // 设置HTTP URI过滤 (key=13)
        if config.HTTPUri != "" {
            key := uint32(13)
            // 将URI字符串转换为哈希值进行匹配
            value := hashString(config.HTTPUri)
            if err := httpFilterMap.Put(key, value); err != nil {
                return fmt.Errorf("设置HTTP URI过滤失败: %v", err)
            }
        }
    }
    
    return nil
}

// HTTP方法字符串转数字
func stringToHTTPMethod(method string) uint32 {
    switch method {
    case "GET":     return 1
    case "POST":    return 2
    case "PUT":     return 3
    case "DELETE":  return 4
    case "HEAD":    return 5
    case "OPTIONS": return 6
    case "PATCH":   return 7
    case "TRACE":   return 8
    case "CONNECT": return 9
    default:        return 0
    }
}

// 字符串哈希函数
func hashString(s string) uint32 {
    hash := uint32(0)
    for _, c := range s {
        hash = hash*31 + uint32(c)
    }
    return hash
}
```

## 6. 用户态代码结构设计

### 6.1 独立文件组织结构

```
# 独立HTTP/HTTPS监控系统
ebpf/
├── netbee-http.ebpf.c     # 独立HTTP/HTTPS eBPF程序
└── netbee.ebpf.c          # 原有网络监控eBPF程序

cmd/
├── main-http.go           # 独立HTTP/HTTPS监控主程序
└── main.go                # 原有网络监控主程序

pkg/http/                  # 独立HTTP监控包
├── event.go               # HTTP/HTTPS事件结构
├── monitor.go             # HTTP/HTTPS监控逻辑
├── parser.go              # HTTP协议解析
├── filter.go              # HTTP过滤逻辑
└── output.go              # HTTP格式化输出

target/
├── netbee-http            # 独立HTTP/HTTPS监控可执行文件
└── netbee                 # 原有网络监控可执行文件
```

### 6.2 独立实现优势

1. **完全独立**：与现有网络监控系统完全分离，互不影响
2. **专门优化**：针对HTTP/HTTPS协议专门优化
3. **独立部署**：可以独立编译、部署和运行
4. **独立维护**：HTTP监控功能的维护不影响原有系统
5. **独立扩展**：可以独立添加HTTP/HTTPS相关功能

### 6.3 独立HTTP监控线程设计

```go
// pkg/http/monitor.go
package http

import (
    "context"
    "github.com/cilium/ebpf/ringbuf"
)

type HTTPMonitor struct {
    rb          *ringbuf.Reader
    filterConfig *HTTPFilterConfig
    ctx         context.Context
    cancel      context.CancelFunc
}

// 启动HTTP监控线程
func (hm *HTTPMonitor) Start() {
    go hm.monitorHTTPEvents()
}

// HTTP事件监控循环
func (hm *HTTPMonitor) monitorHTTPEvents() {
    // 独立的HTTP事件处理循环
    // 专门处理HTTP/HTTPS事件
}
```

### 6.4 独立HTTP事件处理

```go
// pkg/http/monitor.go
// HTTP事件处理函数
func (hm *HTTPMonitor) handleHTTPEvent(event *HTTPEvent) {
    // 应用HTTP特定过滤
    if !hm.applyHTTPFilters(event) {
        return
    }
    
    // 格式化输出HTTP事件
    hm.formatHTTPOutput(event)
}

// HTTP过滤逻辑
func (hm *HTTPMonitor) applyHTTPFilters(event *HTTPEvent) bool {
    // 协议过滤
    // 方法过滤
    // 状态码过滤
    // URI过滤
}
```

### 6.5 独立HTTP格式化输出

```go
// pkg/http/output.go
// 格式化HTTP事件输出
func (hm *HTTPMonitor) formatHTTPOutput(event *HTTPEvent) {
    // 格式化时间戳
    timestamp := time.Unix(0, int64(event.TimestampNs)).Format("15:04:05.000")
    
    // 确定协议类型
    protocol := "http"
    if event.TlsHandshakeResult > 0 {
        protocol = "https"
    }
    
    // 构建Info字段，采用与现有网络监控一致的格式
    info := fmt.Sprintf("%d->%d %s %s", 
        event.SrcPort, event.DstPort, event.Method, event.RequestUri)
    
    // 添加请求参数（如果有）
    if len(event.RequestParams) > 0 && event.RequestParams != "{}" {
        info += fmt.Sprintf(" params:%s", event.RequestParams)
    }
    
    // 添加TLS信息（仅HTTPS）
    if protocol == "https" {
        tlsStatus := "fail"
        if event.TlsHandshakeResult == TLS_HANDSHAKE_SUCCESS {
            tlsStatus = "success"
        }
        info += fmt.Sprintf(" tls:%s", tlsStatus)
    }
    
    // 添加响应体（如果启用）
    if hm.parseBody && event.BodyLen > 0 {
        info += fmt.Sprintf(" body:%s", event.ResponseBody)
    }
    
    // 输出格式化结果
    fmt.Printf("%-19s %-15s %-15s %-8s %-3d %-6s %-6d %s\n",
        timestamp, 
        intToIP(event.SrcAddr), 
        intToIP(event.DstAddr),
        protocol,
        event.Ttl,
        event.Method,
        event.StatusCode,
        info)
}
```
```

## 7. 数据流设计

### 7.1 HTTP请求监控流程

```
1. 用户发起HTTP请求
   ↓
2. eBPF Socket Filter捕获网络数据包
   ↓
3. 解析TCP数据中的HTTP请求
   ↓
4. 生成http_event并发送到ring buffer
   ↓
5. 用户态HTTP监控线程读取事件
   ↓
6. 应用过滤条件并输出
```

### 7.2 HTTPS请求监控流程

```
1. 用户发起HTTPS请求
   ↓
2. eBPF Socket Filter捕获网络数据包
   ↓
3. eBPF Uprobe监控TLS握手过程
   ↓
4. eBPF Uprobe监控SSL读写操作
   ↓
5. 解析SSL数据中的HTTP请求/响应
   ↓
6. 生成http_event并发送到ring buffer
   ↓
7. 用户态HTTP监控线程读取事件
   ↓
8. 应用过滤条件并输出
```

## 8. 输出格式设计

### 8.1 HTTP事件输出格式

```
time                SrcIP          DstIP          Protocol  TTL  Method  Status  Info
15:04:05.123        192.168.1.100  192.168.1.1   http      64   GET     200     54321->80 GET /api/users body:{"users":[{"id":1,"name":"John"}]}
15:04:06.456        192.168.1.100  192.168.1.1   http      64   POST    401     54322->80 POST /api/login params:{"username":"admin","password":"***"} body:{"error":"unauthorized"}
```

### 8.2 HTTPS事件输出格式

```
time                SrcIP          DstIP          Protocol  TTL  Method  Status  Info
15:04:05.123        192.168.1.100  192.168.1.1   https     64   GET     200     54321->443 GET /api/secure tls:success body:{"data":"secure"}
15:04:06.456        192.168.1.100  192.168.1.1   https     64   POST    401     54322->443 POST /api/secure/login params:{"token":"***"} tls:success body:{"error":"unauthorized"}
```

### 8.3 Info字段详细说明

Info字段采用与现有网络监控一致的格式，包含以下信息（按顺序显示）：
- `源端口->目标端口` - 端口信息（格式：54321->80）
- `HTTP方法 URI路径` - 请求方法和路径（如：GET /api/users）
- `params:参数` - 请求参数（GET查询参数或POST表单数据，可选）
- `tls:状态` - TLS握手状态（仅HTTPS，success/fail，可选）
- `body:内容` - 响应体内容（可选，通过-body参数控制）

### 8.4 参数解析示例

```
# GET请求带查询参数
Info: 54321->8080 GET /api/search params:{"q":"keyword","page":"1"}

# POST请求带表单数据
Info: 54322->80 POST /api/login params:{"username":"admin","password":"***"}

# HTTPS请求
Info: 54323->443 GET /api/secure tls:success body:{"status":"ok"}

# 带响应体的请求（-body参数）
Info: 54324->80 GET /api/users body:{"users":[{"id":1,"name":"John"}]}

# 简单GET请求
Info: 54325->80 GET /index.html
```

### 8.5 敏感信息处理

- 密码字段自动脱敏显示为 `***`
- 可通过配置控制哪些字段需要脱敏
- 响应体长度限制，超长内容截断显示

## 9. 性能考虑

### 9.1 eBPF性能优化

- 使用ring buffer减少内存拷贝
- 在eBPF中预过滤，减少用户态处理
- 限制HTTP body解析长度，避免内存溢出
- 使用socket filter直接处理网络数据包，性能最优

### 9.2 用户态性能优化

- 独立线程处理HTTP事件，避免阻塞TCP监控
- 批量处理ring buffer事件
- 异步输出，避免I/O阻塞
- 内存池复用事件结构体

## 10. 错误处理

### 10.1 eBPF错误处理

- 数据解析失败时记录错误但不中断监控
- 内存不足时优雅降级
- Socket filter附加失败时提供详细错误信息

### 10.2 用户态错误处理

- HTTP解析失败时跳过该事件
- 过滤配置错误时提供帮助信息
- 监控线程异常退出时自动重启

## 11. 配置示例

### 11.1 基本HTTP/HTTPS监控

```bash
# 监控所有HTTP和HTTPS流量
./target/netbee-http

# 监控HTTP GET请求
./target/netbee-http -method GET

# 监控HTTP 200响应
./target/netbee-http -status 200

# 监控特定URI
./target/netbee-http -uri "/api/*"

# 监控HTTP/HTTPS并显示响应体
./target/netbee-http -body
```

### 11.2 高级过滤示例

```bash
# 监控特定主机的HTTP/HTTPS请求
./target/netbee-http -host 192.168.1.100

# 监控特定端口的POST请求
./target/netbee-http -dport 8080 -method POST

# 监控API接口的GET请求
./target/netbee-http -uri "/api/*" -method GET

# 监控错误状态码
./target/netbee-http -status 404

# 监控特定来源主机的HTTPS流量
./target/netbee-http -shost 192.168.1.100 -body

# 组合过滤：监控特定主机的API接口POST请求
./target/netbee-http -host 192.168.1.100 -uri "/api/*" -method POST -body

# 监控特定目标主机的所有HTTP/HTTPS流量
./target/netbee-http -dhost 192.168.1.1 -body
```

### 11.3 输出示例

```bash
# 启动监控
./target/netbee-http -body

# 输出示例：
time                SrcIP          DstIP          Protocol  TTL  Method  Status  Info
15:04:05.123        192.168.1.100  192.168.1.1   http      64   GET     200     54321->80 GET /api/users body:{"users":[{"id":1,"name":"John"}]}
15:04:06.456        192.168.1.100  192.168.1.1   https     64   POST    401     54322->443 POST /api/login params:{"username":"admin","password":"***"} tls:success body:{"error":"unauthorized"}
15:04:07.789        192.168.1.100  192.168.1.1   http      64   GET     200     54323->8080 GET /api/search params:{"q":"keyword","page":"1"} body:{"results":[]}
15:04:08.012        192.168.1.100  192.168.1.1   http      64   GET     200     54324->80 GET /index.html
```

## 12. 独立实现示例

### 12.1 独立eBPF程序结构

```c
// ebpf/netbee-http.ebpf.c - 独立HTTP/HTTPS监控eBPF程序
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// HTTP/HTTPS事件结构
struct http_event {
    // 基础网络信息
    __u32 src_addr;
    __u32 dst_addr;
    __u32 ip_proto;
    __u8 src_mac[6];
    __u8 dst_mac[6];
    __u8 ttl;
    __u32 ifindex;
    __u16 src_port;
    __u16 dst_port;
    __u8 tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_len;
    __u16 udp_len;
    char func_name[FUNCNAME_MAX_LEN];
    
    // HTTP/HTTPS特有字段
    __u8 http_version;
    char method[16];
    char request_uri[256];
    char request_params[512];
    __u16 status_code;
    __u16 body_len;
    char response_body[1024];
    __u8 tls_handshake_result;
    __u8 rw;
    __u64 timestamp_ns;
};

// HTTP事件ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events SEC(".maps");

// HTTP过滤配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 20);
} http_filter_config SEC(".maps");

// Socket filter监控HTTP/HTTPS流量
SEC("socket")
int handle_http_traffic(struct __sk_buff *skb) {
    // HTTP/HTTPS流量监控逻辑
    // 协议识别、解析、过滤、事件生成
}

// TLS握手监控
SEC("uprobe/do_handshake")
int handle_tls_handshake_entry(struct pt_regs *ctx) {
    // TLS握手开始监控
}

SEC("uretprobe/do_handshake")
int handle_tls_handshake_exit(struct pt_regs *ctx) {
    // TLS握手结束监控
}

// SSL读写监控
SEC("uprobe/SSL_write")
int handle_ssl_write_entry(struct pt_regs *ctx) {
    // SSL写操作监控
}

SEC("uretprobe/SSL_write")
int handle_ssl_write_exit(struct pt_regs *ctx) {
    // SSL写操作完成监控
}

SEC("uprobe/SSL_read")
int handle_ssl_read_entry(struct pt_regs *ctx) {
    // SSL读操作监控
}

SEC("uretprobe/SSL_read")
int handle_ssl_read_exit(struct pt_regs *ctx) {
    // SSL读操作完成监控
}
```

### 12.2 独立用户态程序结构

```go
// cmd/main-http.go - 独立HTTP/HTTPS监控主程序
package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    
    "netbee/pkg/http"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type http_event HTTPMonitor ../ebpf/netbee-http.ebpf.c -- -I/usr/include/x86_64-linux-gnu

func main() {
    // 命令行参数定义
    var (
        parseBody = flag.Bool("body", false, "解析HTTP/HTTPS响应体内容")
        httpMethod = flag.String("method", "", "过滤HTTP请求方法 (例如: GET,POST)")
        httpStatus = flag.Int("status", 0, "过滤HTTP状态码 (例如: 200,404)")
        httpUri = flag.String("uri", "", "过滤HTTP URI模式 (例如: /api/*)")
        shost = flag.String("shost", "", "过滤来源主机IP地址")
        dhost = flag.String("dhost", "", "过滤目标主机IP地址")
        host = flag.String("host", "", "过滤主机IP地址")
        sport = flag.Int("sport", 0, "过滤来源端口")
        dport = flag.Int("dport", 0, "过滤目标端口")
        port = flag.Int("port", 0, "过滤端口")
    )
    flag.Parse()
    
    // 解析过滤配置
    filterConfig, err := http.ParseHTTPFilterConfig(*shost, *dhost, *host,
                                                   *dport, *sport, *port,
                                                   *httpMethod, *httpStatus, *httpUri)
    if err != nil {
        log.Fatalf("解析过滤条件失败: %v", err)
    }
    
    // 移除内存限制
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Failed to remove memlock:", err)
    }
    
    // 加载eBPF程序
    bpfPath := "./target/netbee-http.o"
    bpfSpec, err := ebpf.LoadCollectionSpec(bpfPath)
    if err != nil {
        log.Fatalf("Failed to load eBPF spec: %v", err)
    }
    
    coll, err := ebpf.NewCollection(bpfSpec)
    if err != nil {
        log.Fatalf("Failed to load eBPF collection: %v", err)
    }
    defer coll.Close()
    
    // 设置过滤配置
    if err := http.SetHTTPFilterConfig(coll, filterConfig); err != nil {
        log.Fatalf("设置过滤配置失败: %v", err)
    }
    
    // 创建HTTP监控器
    monitor, err := http.NewHTTPMonitor(coll, filterConfig, *parseBody)
    if err != nil {
        log.Fatalf("创建HTTP监控器失败: %v", err)
    }
    
    // 创建上下文
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 处理中断信号
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\nReceived interrupt, shutting down...")
        cancel()
    }()
    
    // 启动HTTP监控
    monitor.Start(ctx)
    
    // 等待上下文取消
    <-ctx.Done()
    fmt.Println("HTTP监控已停止")
}
```

### 12.3 独立包结构

```go
// pkg/http/event.go - HTTP事件结构定义
package http

import "unsafe"

// HTTPEvent HTTP/HTTPS事件结构
type HTTPEvent struct {
    // 基础网络信息
    SrcAddr  uint32
    DstAddr  uint32
    IPProto  uint32
    SrcMac   [6]uint8
    DstMac   [6]uint8
    TTL      uint8
    IfIndex  uint32
    SrcPort  uint16
    DstPort  uint16
    TcpFlags uint8
    TcpSeq   uint32
    TcpAck   uint32
    TcpLen   uint16
    UdpLen   uint16
    FuncName [32]byte
    
    // HTTP/HTTPS特有字段
    HTTPVersion         uint8
    Method              [16]byte
    RequestUri          [256]byte
    RequestParams       [512]byte
    StatusCode          uint16
    BodyLen             uint16
    ResponseBody        [1024]byte
    TlsHandshakeResult  uint8
    RW                  uint8
    TimestampNs         uint64
}

// pkg/http/filter.go - HTTP过滤配置
package http

type HTTPFilterConfig struct {
    // 网络层过滤
    SrcHost   uint32
    DstHost   uint32
    Host      uint32
    SrcPort   uint16
    DstPort   uint16
    Port      uint16
    
    // HTTP层过滤
    HTTPProto  []string
    HTTPMethod string
    HTTPStatus uint16
    HTTPUri    string
}

// pkg/http/monitor.go - HTTP监控器
package http

type HTTPMonitor struct {
    rb          *ringbuf.Reader
    filterConfig *HTTPFilterConfig
    parseBody   bool
    ctx         context.Context
    cancel      context.CancelFunc
}

func NewHTTPMonitor(coll *ebpf.Collection, config *HTTPFilterConfig, parseBody bool) (*HTTPMonitor, error) {
    // 创建HTTP监控器实例
}

func (hm *HTTPMonitor) Start(ctx context.Context) {
    // 启动HTTP监控线程
}
```

## 13. 独立实现计划

### 13.1 第一阶段：独立eBPF程序开发
1. 创建`ebpf/netbee-http.ebpf.c`文件
2. 实现HTTP事件结构体定义
3. 实现socket filter监控逻辑
4. 实现HTTP协议解析功能
5. 实现HTTP过滤逻辑

### 13.2 第二阶段：独立用户态程序开发
1. 创建`cmd/main-http.go`文件
2. 创建`pkg/http/`包结构
3. 实现HTTP事件处理逻辑
4. 实现HTTP过滤配置管理
5. 实现HTTP格式化输出

### 13.3 第三阶段：HTTPS监控功能
1. 添加TLS握手监控
2. 实现SSL读写hook
3. 添加HTTPS数据解析
4. 完善错误处理

### 13.4 第四阶段：功能完善和测试
1. 添加响应体解析
2. 实现高级过滤功能
3. 性能优化
4. 独立测试和文档完善
5. 独立部署和运行验证

### 13.5 编译和运行

```bash
# 编译独立HTTP监控程序
make build-http

# 运行独立HTTP监控
./target/netbee-http                    # 监控所有HTTP和HTTPS流量
./target/netbee-http -method GET        # 监控GET请求
./target/netbee-http -status 200        # 监控200状态码
./target/netbee-http -body              # 显示响应体
./target/netbee-http -method POST -body # 监控POST请求并显示响应体

# 与原有网络监控并行运行
./target/netbee &                    # 原有网络监控
./target/netbee-http &               # HTTP/HTTPS监控
```

## 14. 测试策略

### 14.1 单元测试
- HTTP协议解析测试
- 过滤逻辑测试
- 事件结构序列化测试

### 14.2 集成测试
- 端到端HTTP监控测试
- HTTPS监控测试
- 性能压力测试

### 14.3 兼容性测试
- 不同HTTP版本支持测试
- 不同TLS版本支持测试
- 各种HTTP客户端兼容性测试

## 15. 安全考虑

### 15.1 数据隐私
- 敏感信息脱敏处理
- 可配置的body解析长度限制
- 支持过滤敏感头部信息

### 15.2 系统安全
- eBPF程序权限最小化
- Socket filter只访问网络数据包，不涉及进程信息
- 防止内存泄漏和溢出

## 16. 扩展性设计

### 16.1 协议扩展
- 支持HTTP/2.0监控
- 支持WebSocket监控
- 支持gRPC监控

### 16.2 功能扩展
- 支持请求重放
- 支持性能分析
- 支持安全检测

---

本设计文档为HTTP/HTTPS监控系统的详细技术规范，为后续的代码实现提供指导。实现过程中应根据实际情况调整具体细节。
