// 独立HTTP监控eBPF程序
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 网络协议定义
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IPPROTO_TCP 6

#define FUNCNAME_MAX_LEN 32
#define MAX_BODY_LENGTH     1024
#define MAX_URI_LENGTH      256
#define MAX_PARAMS_LENGTH   512
#define MAX_METHOD_LENGTH   16

// HTTP版本枚举
#define HTTP_VERSION_1_0    1
#define HTTP_VERSION_1_1    2
#define HTTP_VERSION_2_0    3

// 事件类型
#define HTTP_EVENT_REQUEST  1
#define HTTP_EVENT_RESPONSE 2

// HTTP方法枚举
#define HTTP_METHOD_GET     1
#define HTTP_METHOD_POST    2
#define HTTP_METHOD_PUT     3
#define HTTP_METHOD_DELETE  4
#define HTTP_METHOD_HEAD    5
#define HTTP_METHOD_OPTIONS 6
#define HTTP_METHOD_PATCH   7
#define HTTP_METHOD_TRACE   8
#define HTTP_METHOD_CONNECT 9

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// HTTP事件结构
struct http_event {
    // 基础网络信息
    __u32 src_addr;
    __u32 dst_addr;
    __u32 ip_proto;
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
    
    // HTTP特有字段
    __u8 http_version;
    char method[MAX_METHOD_LENGTH];
    char request_uri[MAX_URI_LENGTH];
    char request_params[MAX_PARAMS_LENGTH];
    __u16 status_code;
    __u16 body_len;
    char response_body[MAX_BODY_LENGTH];
    __u8 rw;                // 读写标识 (0=read, 1=write)
    __u64 timestamp_ns;
};

// HTTP事件ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events SEC(".maps");

// 网络层过滤配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
} filter_config SEC(".maps");

// HTTP过滤配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 20);
} http_filter_config SEC(".maps");

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


// 函数声明
static int apply_network_filters(struct iphdr *iph, __u16 src_port, __u16 dst_port);
static int apply_http_filters(struct http_event *event);
static __u32 string_to_http_method(const char *method);
static __u32 hash_string(const char *str);
static int parse_http_request(const char *data, size_t len, struct http_event *event);
static int parse_http_response(const char *data, size_t len, struct http_event *event);
static int parse_https_data(const char *data, size_t len, struct http_event *event);
static int extract_http_from_ssl(const char *ssl_data, size_t ssl_len, struct http_event *event);
static int ssl_rw_entry(struct pt_regs *ctx, void *ssl, void *buf, int num);
static int ssl_rw_exit(struct pt_regs *ctx, int rw);

// bpf_strncmp实现
static int bpf_strncmp(const char *s1, size_t n, const char *s2) {
    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

// 网络层过滤函数
static int apply_network_filters(struct iphdr *iph, __u16 src_port, __u16 dst_port) {
    __u32 saddr = bpf_ntohl(iph->saddr);
    __u32 daddr = bpf_ntohl(iph->daddr);
    
    // 来源主机过滤
    __u32 src_host_key = 0;
    __u32 *src_host_filter = bpf_map_lookup_elem(&filter_config, &src_host_key);
    if (src_host_filter && *src_host_filter != 0) {
        if (saddr != *src_host_filter) {
            return 0; // 过滤掉
        }
    }
    
    // 目标主机过滤
    __u32 dst_host_key = 5;
    __u32 *dst_host_filter = bpf_map_lookup_elem(&filter_config, &dst_host_key);
    if (dst_host_filter && *dst_host_filter != 0) {
        if (daddr != *dst_host_filter) {
            return 0; // 过滤掉
        }
    }
    
    // 主机过滤（来源或目标主机匹配）
    __u32 host_key = 6;
    __u32 *host_filter = bpf_map_lookup_elem(&filter_config, &host_key);
    if (host_filter && *host_filter != 0) {
        if (saddr != *host_filter && daddr != *host_filter) {
            return 0; // 过滤掉
        }
    }

    // 端口过滤
    __u32 dst_port_key = 2;
    __u32 src_port_key = 3;
    __u32 port_key = 4;
    
    __u32 *dst_port_allowed = bpf_map_lookup_elem(&filter_config, &dst_port_key);
    __u32 *src_port_allowed = bpf_map_lookup_elem(&filter_config, &src_port_key);
    __u32 *port_allowed = bpf_map_lookup_elem(&filter_config, &port_key);
    
    // 如果设置了端口过滤（来源端口或目的端口匹配）
    if (port_allowed && *port_allowed != 0) {
        if (src_port != *port_allowed && dst_port != *port_allowed) {
            return 0; // 过滤掉
        }
    } else {
        // 如果没有设置port过滤，则检查单独的sport和dport过滤
        if (dst_port_allowed && *dst_port_allowed != 0) {
            if (dst_port != *dst_port_allowed) {
                return 0; // 过滤掉
            }
        }
        
        if (src_port_allowed && *src_port_allowed != 0) {
            if (src_port != *src_port_allowed) {
                return 0; // 过滤掉
            }
        }
    }
    
    return 1; // 通过过滤
}

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
    if (bpf_strncmp(method, 3, "GET") == 0) return HTTP_METHOD_GET;
    if (bpf_strncmp(method, 4, "POST") == 0) return HTTP_METHOD_POST;
    if (bpf_strncmp(method, 3, "PUT") == 0) return HTTP_METHOD_PUT;
    if (bpf_strncmp(method, 6, "DELETE") == 0) return HTTP_METHOD_DELETE;
    if (bpf_strncmp(method, 4, "HEAD") == 0) return HTTP_METHOD_HEAD;
    if (bpf_strncmp(method, 7, "OPTIONS") == 0) return HTTP_METHOD_OPTIONS;
    if (bpf_strncmp(method, 5, "PATCH") == 0) return HTTP_METHOD_PATCH;
    if (bpf_strncmp(method, 5, "TRACE") == 0) return HTTP_METHOD_TRACE;
    if (bpf_strncmp(method, 7, "CONNECT") == 0) return HTTP_METHOD_CONNECT;
    return 0;
}

// 字符串哈希函数
static __u32 hash_string(const char *str) {
    __u32 hash = 0;
    for (int i = 0; i < MAX_URI_LENGTH && str[i] != '\0'; i++) {
        hash = hash * 31 + str[i];
    }
    return hash;
}

// 解析HTTP请求行
static int parse_http_request(const char *data, size_t len, struct http_event *event) {
    if (len < 7) {
        return -1;  // 数据太短
    }
    
    // 简单的HTTP方法识别
    if (bpf_strncmp(data, 3, "GET") == 0) {
        event->method[0] = 'G';
        event->method[1] = 'E';
        event->method[2] = 'T';
        event->method[3] = '\0';
    } else if (bpf_strncmp(data, 4, "POST") == 0) {
        event->method[0] = 'P';
        event->method[1] = 'O';
        event->method[2] = 'S';
        event->method[3] = 'T';
        event->method[4] = '\0';
    } else if (bpf_strncmp(data, 3, "PUT") == 0) {
        event->method[0] = 'P';
        event->method[1] = 'U';
        event->method[2] = 'T';
        event->method[3] = '\0';
    } else if (bpf_strncmp(data, 6, "DELETE") == 0) {
        event->method[0] = 'D';
        event->method[1] = 'E';
        event->method[2] = 'L';
        event->method[3] = 'E';
        event->method[4] = 'T';
        event->method[5] = 'E';
        event->method[6] = '\0';
    } else if (bpf_strncmp(data, 4, "HEAD") == 0) {
        event->method[0] = 'H';
        event->method[1] = 'E';
        event->method[2] = 'A';
        event->method[3] = 'D';
        event->method[4] = '\0';
    } else {
        return -1;  // 不支持的方法
    }
    
    // 设置默认HTTP版本
    event->http_version = HTTP_VERSION_1_1;
    
    // 简单的URI提取（从第4个字符开始到第一个空格）
    size_t uri_start = 0;
    if (bpf_strncmp(data, 3, "GET") == 0 || bpf_strncmp(data, 3, "PUT") == 0) {
        uri_start = 4;  // 跳过"GET "或"PUT "
    } else if (bpf_strncmp(data, 4, "POST") == 0 || bpf_strncmp(data, 4, "HEAD") == 0) {
        uri_start = 5;  // 跳过"POST "或"HEAD "
    } else if (bpf_strncmp(data, 6, "DELETE") == 0) {
        uri_start = 7;  // 跳过"DELETE "
    }
    
    // 查找URI结束位置
    size_t uri_len = 0;
    for (size_t i = uri_start; i < len && i < MAX_URI_LENGTH; i++) {
        if (data[i] == ' ') {
            break;
        }
        event->request_uri[uri_len] = data[i];
        uri_len++;
    }
    event->request_uri[uri_len] = '\0';
    
    return 0;  // 成功解析
}

// 解析HTTP响应行
static int parse_http_response(const char *data, size_t len, struct http_event *event) {
    if (len < 12) {  // "HTTP/1.1 200" 最少12个字符
        return -1;  // 数据太短
    }
    
    // 检查是否是HTTP响应
    if (bpf_strncmp(data, 4, "HTTP") != 0) {
        return -1;  // 不是HTTP响应
    }
    
    // 确定HTTP版本
    if (bpf_strncmp(data, 8, "HTTP/1.0") == 0) {
        event->http_version = HTTP_VERSION_1_0;
    } else if (bpf_strncmp(data, 8, "HTTP/1.1") == 0) {
        event->http_version = HTTP_VERSION_1_1;
    } else if (bpf_strncmp(data, 8, "HTTP/2.0") == 0) {
        event->http_version = HTTP_VERSION_2_0;
    } else {
        return -1;  // 不支持的HTTP版本
    }
    
    // 查找状态码
    const char *status_start = NULL;
    for (size_t i = 8; i < len; i++) {
        if (data[i] == ' ') {
            status_start = &data[i + 1];
            break;
        }
    }
    
    if (!status_start) {
        return -1;  // 没有找到状态码
    }
    
    // 解析状态码
    __u16 status_code = 0;
    for (size_t i = 0; i < 3 && i < len - (status_start - data); i++) {
        if (status_start[i] >= '0' && status_start[i] <= '9') {
            status_code = status_code * 10 + (status_start[i] - '0');
        } else {
            break;
        }
    }
    
    event->status_code = status_code;
    
    return 0;  // 成功解析
}

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
        bpf_map_delete_elem(&ssl_bufs, &tid);
        return 0;
    }
    
    // 分配数据缓冲区
    __u32 zero = 0;
    struct http_event *event = bpf_map_lookup_elem(&ssl_data_buffer, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_bufs, &tid);
        return 0;
    }
    
    // 填充基础信息
    event->rw = rw;  // 0: read, 1: write
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_port = 0;  // SSL uprobe无法获取端口信息
    event->dst_port = 443; // 假设是HTTPS端口
    event->src_addr = 0;
    event->dst_addr = 0;
    event->ip_proto = 6; // TCP
    event->ttl = 64;
    event->tcp_flags = 0;
    event->tcp_seq = 0;
    event->tcp_ack = 0;
    event->tcp_len = 0;
    event->udp_len = 0;
    event->http_version = HTTP_VERSION_1_1;
    event->status_code = 0;
    
    // 读取SSL读写缓冲区的数据
    event->body_len = (size_t)MAX_BODY_LENGTH < (size_t)len ? 
                      (size_t)MAX_BODY_LENGTH : (size_t)len;
    
    if (bufp != NULL) {
        bpf_probe_read_user(event->response_body, event->body_len, (const char *)*bufp);
    }
    
    // 简化版本：直接提交SSL数据，不进行复杂的HTTP解析
    // 创建新的事件并提交到ring buffer
    struct http_event *new_event = bpf_ringbuf_reserve(&http_events, sizeof(*new_event), 0);
    if (new_event) {
        // 只复制关键字段，避免复杂的循环
        new_event->rw = event->rw;
        new_event->timestamp_ns = event->timestamp_ns;
        new_event->src_port = event->src_port;
        new_event->dst_port = event->dst_port;
        new_event->src_addr = event->src_addr;
        new_event->dst_addr = event->dst_addr;
        new_event->ip_proto = event->ip_proto;
        new_event->ttl = event->ttl;
        new_event->tcp_flags = event->tcp_flags;
        new_event->tcp_seq = event->tcp_seq;
        new_event->tcp_ack = event->tcp_ack;
        new_event->tcp_len = event->tcp_len;
        new_event->udp_len = event->udp_len;
        new_event->http_version = event->http_version;
        new_event->status_code = event->status_code;
        new_event->body_len = event->body_len;
        
        // 设置HTTPS标识
        new_event->method[0] = 'H';
        new_event->method[1] = 'T';
        new_event->method[2] = 'T';
        new_event->method[3] = 'P';
        new_event->method[4] = 'S';
        new_event->method[5] = '\0';
        
        // 复制响应体数据（限制长度避免验证器问题）
        int copy_len = event->body_len < MAX_BODY_LENGTH ? event->body_len : MAX_BODY_LENGTH;
        for (int i = 0; i < copy_len && i < MAX_BODY_LENGTH; i++) {
            new_event->response_body[i] = event->response_body[i];
        }
        
        bpf_ringbuf_submit(new_event, 0);
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
    bpf_printk("handle_ssl_write_entry");
    return ssl_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_write")
int handle_ssl_write_exit(struct pt_regs *ctx) {
    bpf_printk("handle_ssl_write_exit");
    return ssl_rw_exit(ctx, 1);  // 1: write
}

// SSL读操作监控
SEC("uprobe/SSL_read")
int handle_ssl_read_entry(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    bpf_printk("handle_ssl_read_entry");
    return ssl_rw_entry(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_read")
int handle_ssl_read_exit(struct pt_regs *ctx) {
    bpf_printk("handle_ssl_read_exit");
    return ssl_rw_exit(ctx, 0);  // 0: read
}

// 使用socket filter直接监控HTTP数据包
SEC("socket")
int handle_http_traffic(struct __sk_buff *skb) {
    struct http_event *event;
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcph;

    // bpf_printk("handle_http_traffic...");
    
    // 读取以太网头部
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP) {
        // bpf_printk("ERROR:not IP packet");
        return 0;
    }
    
    // 读取IP头部
    bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));
    if (iph.protocol != IPPROTO_TCP) {
        // bpf_printk("ERROR:not TCP packet");
        return 0;
    }
    
    // 读取TCP头部
    bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4), &tcph, sizeof(tcph));
    
    // 获取端口信息
    __u16 src_port = bpf_ntohs(tcph.source);
    __u16 dst_port = bpf_ntohs(tcph.dest);
    
    // 应用网络层过滤
    if (apply_network_filters(&iph, src_port, dst_port) == 0) {
        // bpf_printk("ERROR:apply_network_filters failed");
        return 0;  // 被过滤掉
    }
    
    // 计算应用层数据偏移和长度
    __u32 app_offset = ETH_HLEN + (iph.ihl * 4) + (tcph.doff * 4);
    __u32 app_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4) - (tcph.doff * 4);
    
    if (app_len < 7) {
        bpf_printk("ERROR:app_len < 7");
        return 0;
    }
    
    // 通过协议内容识别HTTP流量
    char start_buffer[10] = { };
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
        bpf_printk("ERROR:not HTTP packet %s", start_buffer);
        return 0;  // 不是HTTP协议，过滤掉
    }

    // 分配事件结构
    event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("ERROR:not event");
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
    
    // 设置读写标识：根据端口判断是请求还是响应
    // 如果目标端口是80/443，通常是客户端发送请求 (write=1)
    // 如果源端口是80/443，通常是服务器发送响应 (read=0)
    if (dst_port == 80 || dst_port == 443) {
        event->rw = 1;  // 客户端请求
    } else {
        event->rw = 0;  // 服务器响应
    }
    
    // 复制目标MAC地址
    for (int i = 0; i < 6; i++) {
        event->dst_mac[i] = eth.h_dest[i];
    }
    
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
                bpf_printk("apply_http_filters success");
            } else {
                bpf_printk("ERROR:apply_http_filters failed");
                bpf_ringbuf_discard(event, 0);
            }
        } else {
            bpf_ringbuf_discard(event, 0);
            bpf_printk("ERROR:parse_http_request or parse_http_response failed");
        }
    } else {
        bpf_printk("ERROR:app_len > sizeof(event->response_body)");
        bpf_ringbuf_discard(event, 0);
    }
    
    return 0;
}