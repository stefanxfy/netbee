// For CO-RE access to struct sk_buff in kprobe context
#include "vmlinux.h"
// #include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define FUNCNAME_MAX_LEN 32

// 网络数据包事件结构
struct so_event {
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
    __u32 pid;          // 进程ID
    __u64 stack_trace[64];  // 调用栈信息，最多64层
    __u32 stack_depth;  // 调用栈深度
    
    // 新增：Netfilter 相关字段
    __u8 nf_hook;       // Netfilter 钩子点 (NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, 等)
    __s8 verdict;       // 处理结果 (1=OKFN_NEEDED, -1=DROP, 0=OTHER)
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 网络数据包事件的 ring buffer
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 过滤配置map
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 10);
} filter_config SEC(".maps");

// kfree配置map
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} kfree_config SEC(".maps");

// nf_hook_slow 中间状态结构体
struct nf_hook_slow_state {
    unsigned int hook;                      // 钩子点
    struct sk_buff *skb;                    // 数据包指针
    __u64 start_ns;                         // 开始时间戳（用于调试）
};

// nf_hook_slow 状态哈希表
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct nf_hook_slow_state);
	__uint(max_entries, 512);
} nf_hook_slow_states SEC(".maps");

// skb 元数据结构体
struct skb_metadata {
    __u8 nf_hook;       // Netfilter 钩子点
    __s8 verdict;       // Netfilter 处理结果
};

// skb 元数据哈希表，使用与 nf_hook_slow_states 相同的键
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct skb_metadata);
	__uint(max_entries, 1024);
} skb_metadata_map SEC(".maps");

// 生成唯一键值的函数
static __u32 generate_nf_hook_key(void) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)(pid_tgid & 0xFFFFFFFF);
    
    // 使用简单的哈希算法生成唯一键
    return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
}

// 参数过滤函数
static int apply_filters(struct iphdr *iph, __u16 src_port, __u16 dst_port) {
    // 从map中读取过滤配置
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

    // 协议过滤
    __u32 proto_key = 1;
    __u32 *proto_allowed = bpf_map_lookup_elem(&filter_config, &proto_key);
    if (proto_allowed && *proto_allowed != 0) {
        __u32 allowed_proto = *proto_allowed;
        if (iph->protocol != allowed_proto) {
            return 0; // 过滤掉
        }
    }

    // 端口过滤：检查来源端口或目的端口
    __u32 dst_port_key = 2;  // 目的端口过滤键
    __u32 src_port_key = 3;  // 来源端口过滤键
    __u32 port_key = 4;      // 端口过滤键（来源端口或目的端口匹配）
    
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
        // 如果设置了目的端口过滤
        if (dst_port_allowed && *dst_port_allowed != 0) {
            if (dst_port != *dst_port_allowed) {
                return 0; // 过滤掉
            }
        }
        
        // 如果设置了来源端口过滤
        if (src_port_allowed && *src_port_allowed != 0) {
            if (src_port != *src_port_allowed) {
                return 0; // 过滤掉
            }
        }
    }
    
    return 1; // 通过过滤
}

// 核心的 skb 解析和事件生成函数
static int do_trace_skb(struct pt_regs *ctx, struct sk_buff *skb, const char *func_name) {

    bpf_printk("%s: do_trace_skb", func_name);
    if (!skb) {
        bpf_printk("%s: skb is NULL", func_name);
        return 0;
    }
    
    // 获取网卡信息
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    __u32 ifindex = 0;
    if (dev) {
        ifindex = BPF_CORE_READ(dev, ifindex);
    }

    // Read pointers/offsets from skb using CO-RE helpers
    __u16 nhoff = BPF_CORE_READ(skb, network_header);
    __u16 mhoff = BPF_CORE_READ(skb, mac_header);
    unsigned char *head = BPF_CORE_READ(skb, head);

    // 解析以太网头获取 MAC 地址
    void *eth_ptr = (void *)(head + mhoff);
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), eth_ptr) != 0) {
        bpf_printk("%s: bpf_probe_read_kernel eth error", func_name);
        // 设置默认的 MAC 地址
        __builtin_memset(eth.h_source, 0, 6);
        __builtin_memset(eth.h_dest, 0, 6);
    }

    // Compute IPv4 header pointer
    void *iph_ptr = (void *)(head + nhoff);
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), iph_ptr) != 0) {
        bpf_printk("%s: bpf_probe_read_kernel iph error", func_name);
        return 0;
    }

    // Filter only IPv4
    if ((iph.version & 0xF) != 4) {
        bpf_printk("%s: iph.version & 0xF != 4", func_name);
        return 0;
    }

    // 解析端口信息（仅对 TCP 和 UDP）
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 tcp_flags = 0;
    __u32 tcp_seq = 0;
    __u32 tcp_ack = 0;
    __u16 tcp_len = 0;
    __u16 udp_len = 0;
    
    if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
        // 计算传输层头部偏移
        __u8 ihl = iph.ihl;  // IP头部长度（以4字节为单位）
        if (ihl < 5) ihl = 5; // 最小IP头部长度
        __u32 transport_offset = nhoff + (ihl * 4);
        
        // 读取传输层头部（优先使用协议头字段解析端口，避免端序拆分歧义）
        void *transport_ptr = (void *)(head + transport_offset);
        if (iph.protocol == IPPROTO_TCP) {
            struct tcphdr tcp_hdr;
            if (bpf_probe_read_kernel(&tcp_hdr, sizeof(tcp_hdr), transport_ptr) == 0) {
                // 使用 tcphdr 的 source/dest 字段，端序转换后得到正确方向
                src_port = bpf_ntohs(tcp_hdr.source);
                dst_port = bpf_ntohs(tcp_hdr.dest);

                tcp_flags = tcp_hdr.fin | (tcp_hdr.syn << 1) | (tcp_hdr.rst << 2) | (tcp_hdr.psh << 3) | (tcp_hdr.ack << 4) | (tcp_hdr.urg << 5) | (tcp_hdr.ece << 6) | (tcp_hdr.cwr << 7);
                tcp_seq = bpf_ntohl(tcp_hdr.seq);
                tcp_ack = bpf_ntohl(tcp_hdr.ack_seq);

                // 计算TCP数据长度 = IP总长度 - IP头部长度 - TCP头部长度
                __u16 ip_total_len = bpf_ntohs(iph.tot_len);
                __u8 tcp_header_len = (tcp_hdr.doff) * 4;  // TCP头部长度（以4字节为单位）
                if (tcp_header_len >= 20 && tcp_header_len <= 60) {  // TCP头部长度范围检查
                    __u16 ip_header_len = ihl * 4;
                    if (ip_total_len > ip_header_len + tcp_header_len) {
                        tcp_len = ip_total_len - ip_header_len - tcp_header_len;
                    } else {
                        tcp_len = 0;  // 没有数据部分
                    }
                } else {
                    tcp_len = 0;  // 无效的TCP头部长度
                }
            }
        } else if (iph.protocol == IPPROTO_UDP) {
            struct udphdr udp_hdr;
            if (bpf_probe_read_kernel(&udp_hdr, sizeof(udp_hdr), transport_ptr) == 0) {
                // 使用 udphdr 的 source/dest 字段，端序转换
                src_port = bpf_ntohs(udp_hdr.source);
                dst_port = bpf_ntohs(udp_hdr.dest);

                // UDP长度 = UDP头部中的长度字段 - UDP头部长度(8字节)
                __u16 udp_total_len = bpf_ntohs(udp_hdr.len);
                if (udp_total_len >= 8) {  // UDP最小头部长度
                    udp_len = udp_total_len - 8;  // 减去UDP头部长度
                } else {
                    udp_len = 0;  // 无效的UDP长度
                }
            }
        }
    }

    // 内联过滤逻辑（从 apply_filters 函数）
    __u32 saddr = bpf_ntohl(iph.saddr);
    __u32 daddr = bpf_ntohl(iph.daddr);
    
    // 来源主机过滤
    __u32 src_host_key = 0;
    __u32 *src_host_filter = bpf_map_lookup_elem(&filter_config, &src_host_key);
    if (src_host_filter && *src_host_filter != 0) {
        if (saddr != *src_host_filter) {
            bpf_printk("%s: saddr != *src_host_filter", func_name);
            return -1; // 过滤掉
        }
    }
    
    // 目标主机过滤
    __u32 dst_host_key = 5;
    __u32 *dst_host_filter = bpf_map_lookup_elem(&filter_config, &dst_host_key);
    if (dst_host_filter && *dst_host_filter != 0) {
        if (daddr != *dst_host_filter) {
            bpf_printk("%s: daddr != *dst_host_filter", func_name);
            return -1; // 过滤掉
        }
    }
    
    // 主机过滤（来源或目标主机匹配）
    __u32 host_key = 6;
    __u32 *host_filter = bpf_map_lookup_elem(&filter_config, &host_key);
    if (host_filter && *host_filter != 0) {
        if (saddr != *host_filter && daddr != *host_filter) {
            bpf_printk("%s: saddr != *host_filter && daddr != *host_filter", func_name);
            return -1; // 过滤掉
        }
    }

    // 协议过滤
    __u32 proto_key = 1;
    __u32 *proto_allowed = bpf_map_lookup_elem(&filter_config, &proto_key);
    if (proto_allowed && *proto_allowed != 0) {
        __u32 allowed_proto = *proto_allowed;
        if (iph.protocol != allowed_proto) {
            bpf_printk("%s: iph.protocol != allowed_proto", func_name);
            return -1; // 过滤掉
        }
    }

    // 端口过滤：检查来源端口或目的端口
    __u32 dst_port_key = 2;  // 目的端口过滤键
    __u32 src_port_key = 3;  // 来源端口过滤键
    __u32 port_key = 4;      // 端口过滤键（来源端口或目的端口匹配）
    
    __u32 *dst_port_allowed = bpf_map_lookup_elem(&filter_config, &dst_port_key);
    __u32 *src_port_allowed = bpf_map_lookup_elem(&filter_config, &src_port_key);
    __u32 *port_allowed = bpf_map_lookup_elem(&filter_config, &port_key);


    // 打印 目的端口
    bpf_printk("%s-dst_port: %d", func_name, dst_port);

    // 如果设置了端口过滤（来源端口或目的端口匹配）
    if (port_allowed && *port_allowed != 0) {
        if (src_port != *port_allowed && dst_port != *port_allowed) {
            bpf_printk("%s: src_port != *port_allowed && dst_port != *port_allowed", func_name);
            bpf_printk("%s: src_port: %d, dst_port: %d", func_name, src_port, dst_port);
            return -1; // 过滤掉
        }
    } else {
        // 如果没有设置port过滤，则检查单独的sport和dport过滤
        // 如果设置了目的端口过滤
        if (dst_port_allowed && *dst_port_allowed != 0) {
            if (dst_port != *dst_port_allowed) {
                bpf_printk("%s: dst_port != *dst_port_allowed", func_name);
                return -1; // 过滤掉
            }
        }
        
        // 如果设置了来源端口过滤
        if (src_port_allowed && *src_port_allowed != 0) {
            if (src_port != *src_port_allowed) {
                bpf_printk("%s: src_port != *src_port_allowed", func_name);
                return -1; // 过滤掉
            }
        }
    }

    bpf_printk("%s-filter-done", func_name);

    struct so_event *e;
    // 申请 ring buffer 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("%s: bpf_ringbuf_reserve error", func_name);
        return 0;
    }

    // 填充事件数据
    e->ip_proto = (__u32)iph.protocol;
    e->src_addr = saddr;
    e->dst_addr = daddr;
    e->ttl = iph.ttl;
    e->ifindex = ifindex;
    e->src_port = src_port;
    e->dst_port = dst_port;
    
    // 填充TCP相关字段
    e->tcp_flags = tcp_flags;
    e->tcp_seq = tcp_seq;
    e->tcp_ack = tcp_ack;
    e->tcp_len = tcp_len;
    
    // 填充UDP相关字段
    e->udp_len = udp_len;
    
    // 填充 MAC 地址
    __builtin_memcpy(e->src_mac, eth.h_source, 6);
    __builtin_memcpy(e->dst_mac, eth.h_dest, 6);


    bpf_printk("%s-fill-event-data-done", func_name);
    
    // 填充函数名
    bpf_core_read_str(e->func_name, FUNCNAME_MAX_LEN, func_name);
    
    // 获取当前进程ID
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    // 初始化其他字段
    e->stack_depth = 0;
    
    // 从 skb 元数据映射中查找 Netfilter 信息
    // 只有当函数名是 nf_hook_slow 时才查找 NF 元数据
    e->nf_hook = 0;
    e->verdict = 0;
    
    // 检查是否是 nf_hook_slow 函数
    if (func_name[0] == 'n' && func_name[1] == 'f' && 
        func_name[2] == '_' && func_name[3] == 'h' && 
        func_name[4] == 'o' && func_name[5] == 'o' && 
        func_name[6] == 'k' && func_name[7] == '_' && 
        func_name[8] == 's' && func_name[9] == 'l' && 
        func_name[10] == 'o' && func_name[11] == 'w') {
        
        // 生成相同的 key
        __u32 nf_key = generate_nf_hook_key();
        struct skb_metadata *metadata = bpf_map_lookup_elem(&skb_metadata_map, &nf_key);
        if (metadata) {
            e->nf_hook = metadata->nf_hook;
            e->verdict = metadata->verdict;
            bpf_map_delete_elem(&skb_metadata_map, &nf_key);
            bpf_printk("nf_hook_slow: found skb metadata with key=%u: nf_hook=%u, verdict=%d", nf_key, metadata->nf_hook, metadata->verdict);
        } else {
            bpf_printk("nf_hook_slow: no skb metadata found for key=%u, using defaults", nf_key);
        }
    } else {
        bpf_printk("%s: not nf_hook_slow function, skipping NF metadata lookup", func_name);
    }
    
    // 检查是否需要获取 kfree 调用栈信息
    __u32 kfree_key = 0;
    __u32 *kfree_enabled = bpf_map_lookup_elem(&kfree_config, &kfree_key);
    
    if (kfree_enabled && *kfree_enabled) {
        bpf_printk("kfree_enabled: %d", *kfree_enabled);
        // 检查是否是 kfree_skb 函数调用
        // 由于 func_name 是编译时常量，我们直接比较指针
        // 检查函数名是否以 "kfree" 开头
        if (func_name[0] == 'k' && func_name[1] == 'f' && 
            func_name[2] == 'r' && func_name[3] == 'e' && 
            func_name[4] == 'e') {
            bpf_printk("kfree function detected, getting stack trace");
            // 获取调用栈信息
            e->stack_depth = bpf_get_stack(ctx, e->stack_trace, sizeof(e->stack_trace), 0);
            if (e->stack_depth < 0) {
                e->stack_depth = 0;
            }
            bpf_printk("kfree stack trace captured, depth=%u", e->stack_depth);
        } else {
            bpf_printk("not a kfree function, first char: %c", func_name[0]);
        }
    } else {
        bpf_printk("kfree not enabled or config not found");
    }
    
    // 内联提交逻辑（从 submit_event 函数）
    bpf_ringbuf_submit(e, 0);
    bpf_printk("%s-Event-submitted-successfully", func_name);
    return 1;
}

// kprobe on netif_rx to capture incoming packets and emit minimal metadata
SEC("kprobe/netif_rx")
int handle_netif_rx(struct pt_regs *ctx)
{
    bpf_printk("netif_rx...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("netif_rx: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("netif_rx: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("netif_rx: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on ip_rcv to capture IP layer packet processing
SEC("kprobe/ip_rcv")
int handle_ip_rcv(struct pt_regs *ctx)
{
    bpf_printk("ip_rcv...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("ip_rcv: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("ip_rcv: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("ip_rcv: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on ip_local_deliver to capture local packet delivery
SEC("kprobe/ip_local_deliver")
int handle_ip_local_deliver(struct pt_regs *ctx)
{
    bpf_printk("ip_local_deliver...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("ip_local_deliver: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("ip_local_deliver: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("ip_local_deliver: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on dev_queue_xmit to capture device transmission
SEC("kprobe/dev_queue_xmit")
int handle_dev_queue_xmit(struct pt_regs *ctx)
{
    bpf_printk("dev_queue_xmit...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("dev_queue_xmit: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("dev_queue_xmit: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("dev_queue_xmit: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on tcp_v4_rcv to capture TCP IPv4 packet reception
SEC("kprobe/tcp_v4_rcv")
int handle_tcp_v4_rcv(struct pt_regs *ctx)
{
    bpf_printk("tcp_v4_rcv...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("tcp_v4_rcv: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("tcp_v4_rcv: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("tcp_v4_rcv: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on udp_rcv to capture UDP packet reception
SEC("kprobe/udp_rcv")
int handle_udp_rcv(struct pt_regs *ctx)
{
    bpf_printk("udp_rcv...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("udp_rcv: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("udp_rcv: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("udp_rcv: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on icmp_rcv to capture ICMP packet reception
SEC("kprobe/icmp_rcv")
int handle_icmp_rcv(struct pt_regs *ctx)
{
    bpf_printk("icmp_rcv...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("icmp_rcv: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("icmp_rcv: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("icmp_rcv: do_trace_skb filtered");
    }
    return 0;
}


// kprobe on icmp_echo to capture ICMP echo request
SEC("kprobe/icmp_echo")
int handle_icmp_echo(struct pt_regs *ctx)
{
    bpf_printk("icmp_echo...");
    // struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    return 0;
}

// kprobe on icmp_unreach to capture ICMP unreachable messages
SEC("kprobe/icmp_unreach")
int handle_icmp_unreach(struct pt_regs *ctx)
{
    bpf_printk("icmp_unreach...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("icmp_unreach: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("icmp_unreach: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("icmp_unreach: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on tcp_transmit_skb to capture TCP packet transmission
SEC("kprobe/tcp_transmit_skb")
int handle_tcp_transmit_skb(struct pt_regs *ctx)
{
    bpf_printk("tcp_transmit_skb...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("tcp_transmit_skb: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("tcp_transmit_skb: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("tcp_transmit_skb: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on ip_queue_xmit to capture IP packet queuing
SEC("kprobe/ip_queue_xmit")
int handle_ip_queue_xmit(struct pt_regs *ctx)
{
    bpf_printk("ip_queue_xmit...");
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct flowi4 *fl4 = (struct flowi4 *)PT_REGS_PARM3(ctx);
    
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("ip_queue_xmit: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("ip_queue_xmit: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("ip_queue_xmit: do_trace_skb filtered");
    }
    return 0;
}

// kprobe on kfree_skb to capture skb memory release
SEC("kprobe/kfree_skb")
int handle_kfree_skb(struct pt_regs *ctx)
{
    bpf_printk("kfree_skb...");
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    // 直接调用 do_trace_skb，它内部会处理所有逻辑并提交事件
    int result = do_trace_skb(ctx, skb, __func__+7);
    if (result == 1) {
        bpf_printk("kfree_skb: do_trace_skb success");
    } else if (result == 0) {
        bpf_printk("kfree_skb: do_trace_skb failed");
    } else if (result == -1) {
        bpf_printk("kfree_skb: do_trace_skb filtered");
    }
    return 0;
}


// kprobe on nf_hook_slow to capture Netfilter processing
// https://elixir.bootlin.com/linux/v6.15.11/source/net/netfilter/core.c
SEC("kprobe/nf_hook_slow")
int handle_nf_hook_slow(struct pt_regs *ctx)
{
    bpf_printk("handle_nf_hook_slow entry...");
    
    // 从 pt_regs 中提取 nf_hook_slow 函数的关键参数
    // 根据源码：int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, ...)
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx); // 数据包指针
    struct nf_hook_state *nf_state = (struct nf_hook_state *)PT_REGS_PARM2(ctx); // 钩子状态
    
    // 从 nf_state 中获取钩子点信息
    unsigned int hook = 0;
    if (nf_state) {
        // 使用 BPF_CORE_READ 安全地读取 nf_state->hook
        hook = BPF_CORE_READ(nf_state, hook);
    }
    
    // 验证参数合理性
    if (hook > 4) {
        bpf_printk("handle_nf_hook_slow: invalid hook value %u", hook);
        return 0;
    }
    
    // 生成唯一键值
    __u32 key = generate_nf_hook_key();
    
    // 创建简化的状态结构体
    struct nf_hook_slow_state state;
    __builtin_memset(&state, 0, sizeof(state));  // 初始化整个结构体
    state.hook = hook;
    state.skb = skb;
    state.start_ns = bpf_ktime_get_ns();  // 仅用于调试
    
    // 存储到哈希表
    int ret = bpf_map_update_elem(&nf_hook_slow_states, &key, &state, BPF_ANY);
    if (ret != 0) {
        bpf_printk("handle_nf_hook_slow: failed to store state, ret=%d", ret);
    } else {
        bpf_printk("handle_nf_hook_slow: stored state with key=%u, hook=%u, skb=%p", key, hook, skb);
    }
    
    return 0;
}

// kretprobe on nf_hook_slow to capture verdict only
SEC("kretprobe/nf_hook_slow")
int handle_nf_hook_slow_ret(struct pt_regs *ctx)
{
    bpf_printk("nf_hook_slow_ret exit...");
    
    // 获取函数返回值（verdict）
    // PT_REGS_RC 返回 64 位值，需要正确处理有符号整数的转换
    // 使用简单的类型转换，让编译器处理符号扩展
    __s64 rc_signed = (__s64)PT_REGS_RC(ctx);
    int verdict = (int)rc_signed;
    
    // 添加调试信息
    bpf_printk("nf_hook_slow_ret: raw_rc=0x%llx, signed_rc=%lld, verdict=%d", 
               PT_REGS_RC(ctx), rc_signed, verdict);
    
    // 生成相同的键值
    __u32 key = generate_nf_hook_key();
    
    // 查找对应的状态
    struct nf_hook_slow_state *state = bpf_map_lookup_elem(&nf_hook_slow_states, &key);
    if (!state) {
        bpf_printk("nf_hook_slow_ret: state not found for key=%u", key);
        return 0;
    }
    
    // 直接使用存储的 skb
    struct sk_buff *skb = state->skb;
    if (!skb) {
        bpf_printk("nf_hook_slow_ret: skb is NULL");
        bpf_map_delete_elem(&nf_hook_slow_states, &key);
        return 0;
    }
    
    // 在调用 do_trace_skb 之前，先设置 skb 的元数据
    struct skb_metadata metadata = {
        .nf_hook = state->hook,
        .verdict = verdict
    };
    
    // 将 skb 元数据存储到映射中，使用相同的 key
    int ret = bpf_map_update_elem(&skb_metadata_map, &key, &metadata, BPF_ANY);
    if (ret != 0) {
        bpf_printk("nf_hook_slow_ret: failed to store skb metadata, ret=%d", ret);
    } else {
        bpf_printk("nf_hook_slow_ret: stored skb metadata with key=%u: nf_hook=%u, verdict=%d", key, state->hook, verdict);
    }
    
    // 调用 do_trace_skb，它会从映射中查找 skb 元数据
    int result = do_trace_skb(ctx, skb, "nf_hook_slow");
    if (result == 1) {
        bpf_printk("nf_hook_slow_ret: do_trace_skb-success. nf_hook_slow_ret: nf_hook=%u, verdict=%u", state->hook, verdict);
    } else if (result == 0) {
        bpf_printk("nf_hook_slow_ret: do_trace_skb-failed. nf_hook_slow_ret: nf_hook=%u, verdict=%u", state->hook, verdict);
    } else if (result == -1) {
        bpf_printk("nf_hook_slow_ret: do_trace_skb-filtered. nf_hook_slow_ret: nf_hook=%u, verdict=%u", state->hook, verdict);
    }
    
    // 清理哈希表
    bpf_map_delete_elem(&nf_hook_slow_states, &key);
    
    bpf_printk("nf_hook_slow_ret: nf_hook=%u, verdict=%u", state->hook, verdict);
    
    return 0;
}