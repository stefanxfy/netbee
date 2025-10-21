# eBPF kprobe 中的 struct pt_regs *ctx 参数详解

## 1. 概述

在 eBPF 程序中，通过 kprobe 挂载到内核函数时，我们会接触到 `struct pt_regs *ctx` 参数。这个参数是理解和利用 eBPF 监控内核行为的关键，它包含了被探测函数的执行上下文信息，尤其是函数参数和返回值。

本文将详细解析在 `SEC("kprobe/ipt_do_table")` 和 `SEC("kprobe/nf_hook_slow")` 中，`struct pt_regs *ctx` 参数可以读取哪些信息，并通过图表形式直观展示 ctx 的组成和偏移。

## 2. struct pt_regs 结构简介

`struct pt_regs` 是一个架构相关的结构体，用于保存处理器的寄存器状态。在 eBPF 程序中，我们主要通过一系列辅助宏来访问这些寄存器，而不是直接操作结构体成员。

### 2.1 pt_regs 架构与寄存器布局

以下是一个简化的 pt_regs 结构示意图，展示了主要寄存器在内存中的布局：

```
+------------------------+
|        指令指针         |   (IP/RIP) - 指向当前执行的指令
+------------------------+
|        栈指针          |   (SP/RSP) - 指向当前栈顶
+------------------------+
|        基址指针         |   (BP/RBP) - 用于函数调用栈帧
+------------------------+
|        通用寄存器       |   (AX/EAX/RAX, BX/EBX/RBX 等)
+------------------------+
|        标志寄存器       |   (EFLAGS/RFLAGS) - 存储状态标志
+------------------------+
|        参数寄存器       |   (用于传递函数参数)
+------------------------+
|        返回值寄存器     |   (存储函数返回值)
+------------------------+
```

### 2.2 eBPF 中访问 pt_regs 的辅助宏

在 eBPF 编程中，我们使用以下宏来访问寄存器内容：

| 宏名 | 功能描述 |
|------|---------|
| PT_REGS_PARM1(ctx) | 获取函数的第一个参数 |
| PT_REGS_PARM2(ctx) | 获取函数的第二个参数 |
| PT_REGS_PARM3(ctx) | 获取函数的第三个参数 |
| PT_REGS_PARM4(ctx) | 获取函数的第四个参数 |
| PT_REGS_PARM5(ctx) | 获取函数的第五个参数 |
| PT_REGS_RC(ctx) | 获取函数的返回值 |

## 3. SEC("kprobe/nf_hook_slow") 中的 ctx 参数分析

### 3.1 nf_hook_slow 函数定义

通过搜索，我们找到了 `nf_hook_slow` 函数的完整定义：

```c
int nf_hook_slow(int pf, unsigned int hook, struct sk_buff **pskb,
                 struct net_device *indev, struct net_device *outdev,
                 int (*okfn)(struct sk_buff *), int hook_thresh)
```

### 3.2 从 ctx 获取 nf_hook_slow 函数参数

基于函数定义，我们可以使用相应的宏从 ctx 中提取各个参数：

| 参数名 | 参数类型 | 描述 | 从 ctx 中获取方法 |
|--------|---------|------|-----------------|
| pf | int | 协议族 (如 PF_INET 表示 IPv4) | PT_REGS_PARM1(ctx) |
| hook | unsigned int | Netfilter 钩子点 (如 NF_INET_PRE_ROUTING) | PT_REGS_PARM2(ctx) |
| pskb | struct sk_buff ** | 指向 sk_buff 指针的指针 (数据包) | PT_REGS_PARM3(ctx) |
| indev | struct net_device * | 输入网络设备 | PT_REGS_PARM4(ctx) |
| outdev | struct net_device * | 输出网络设备 | PT_REGS_PARM5(ctx) |
| okfn | int (*)(struct sk_buff *) | 成功时调用的回调函数 | PT_REGS_PARM6(ctx) |
| hook_thresh | int | 钩子函数优先级阈值 | PT_REGS_PARM7(ctx) |

### 3.3 参数获取示意图

```
+------------------------+   PT_REGS_PARM1(ctx) -> pf (协议族)
|        pt_regs         |   PT_REGS_PARM2(ctx) -> hook (钩子点)
+------------------------+   PT_REGS_PARM3(ctx) -> pskb (数据包指针指针)
|        指令指针         |   PT_REGS_PARM4(ctx) -> indev (输入设备)
+------------------------+   PT_REGS_PARM5(ctx) -> outdev (输出设备)
|        栈指针          |   PT_REGS_PARM6(ctx) -> okfn (回调函数)
+------------------------+   PT_REGS_PARM7(ctx) -> hook_thresh (优先级阈值)
|        通用寄存器       |
+------------------------+
|        参数寄存器       |
+------------------------+
```

### 3.4 示例代码

```c
SEC("kprobe/nf_hook_slow")
int handle_nf_hook_slow(struct pt_regs *ctx) {
    // 获取 nf_hook_slow 函数参数
    int pf = PT_REGS_PARM1(ctx);
    unsigned int hook = PT_REGS_PARM2(ctx);
    struct sk_buff **pskb = (struct sk_buff **)PT_REGS_PARM3(ctx);
    struct net_device *indev = (struct net_device *)PT_REGS_PARM4(ctx);
    struct net_device *outdev = (struct net_device *)PT_REGS_PARM5(ctx);
    int (*okfn)(struct sk_buff *) = (int (*)(struct sk_buff *))PT_REGS_PARM6(ctx);
    int hook_thresh = PT_REGS_PARM7(ctx);
    
    // 可以访问数据包内容
    if (pskb && *pskb) {
        struct sk_buff *skb = *pskb;
        // 使用 BPF_CORE_READ 读取 skb 字段
        // ...
    }
    
    return 0;
}

// 获取返回值示例
SEC("kretprobe/nf_hook_slow")
int handle_nf_hook_slow_ret(struct pt_regs *ctx) {
    int verdict = PT_REGS_RC(ctx); // 获取返回值（判决结果）
    return 0;
}
```

## 4. SEC("kprobe/ipt_do_table") 中的 ctx 参数分析

### 4.1 ipt_do_table 函数参数推断

虽然没有找到 ipt_do_table 函数的完整定义，但根据 Linux 内核中类似函数的模式和 netbee 项目的使用场景，我们可以推断其参数结构。ipt_do_table 函数主要负责处理 iptables 规则表，基于上下文可以推断其参数如下：

```c
unsigned int ipt_do_table(struct sk_buff *skb, 
                          const struct xt_table_info *info, 
                          unsigned int hook,
                          struct xt_action_param *param)
```

### 4.2 从 ctx 获取 ipt_do_table 函数参数

基于推断的函数定义，我们可以尝试从 ctx 中提取各个参数：

| 参数名 | 参数类型 | 描述 | 从 ctx 中获取方法 |
|--------|---------|------|-----------------|
| skb | struct sk_buff * | 网络数据包 | PT_REGS_PARM1(ctx) |
| info | const struct xt_table_info * | iptables 表信息 | PT_REGS_PARM2(ctx) |
| hook | unsigned int | Netfilter 钩子点 | PT_REGS_PARM3(ctx) |
| param | struct xt_action_param * | 动作参数 | PT_REGS_PARM4(ctx) |

### 4.3 参数获取示意图

```
+------------------------+   PT_REGS_PARM1(ctx) -> skb (数据包)
|        pt_regs         |   PT_REGS_PARM2(ctx) -> info (表信息)
+------------------------+   PT_REGS_PARM3(ctx) -> hook (钩子点)
|        指令指针         |   PT_REGS_PARM4(ctx) -> param (动作参数)
+------------------------+
|        栈指针          |
+------------------------+
|        通用寄存器       |
+------------------------+
|        参数寄存器       |
+------------------------+
```

### 4.4 示例代码

```c
SEC("kprobe/ipt_do_table")
int handle_ipt_do_table(struct pt_regs *ctx) {
    // 获取 ipt_do_table 函数参数
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    const struct xt_table_info *info = (const struct xt_table_info *)PT_REGS_PARM2(ctx);
    unsigned int hook = PT_REGS_PARM3(ctx);
    struct xt_action_param *param = (struct xt_action_param *)PT_REGS_PARM4(ctx);
    
    // 访问数据包内容示例
    if (skb) {
        // 使用 BPF_CORE_READ 读取 skb 字段
        __u16 nhoff = BPF_CORE_READ(skb, network_header);
        __u16 mhoff = BPF_CORE_READ(skb, mac_header);
        // ...
    }
    
    return 0;
}

// 获取返回值示例
SEC("kretprobe/ipt_do_table")
int handle_ipt_do_table_ret(struct pt_regs *ctx) {
    unsigned int verdict = PT_REGS_RC(ctx); // 获取返回值（判决结果）
    return 0;
}
```

## 5. 数据包访问与信息提取

从上面的分析可以看出，通过 ctx 获取 skb 参数后，我们可以进一步访问数据包的详细信息。以下是一个综合示例，展示如何从 `struct sk_buff *skb` 中提取网络数据包信息：

```c
// 从 skb 中提取网络数据包信息
void extract_packet_info(struct sk_buff *skb) {
    if (!skb) return;
    
    // 获取网络设备信息
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        __u32 ifindex = BPF_CORE_READ(dev, ifindex);
        // ...处理接口索引
    }
    
    // 读取 skb 中的头部偏移量
    __u16 nhoff = BPF_CORE_READ(skb, network_header);
    __u16 mhoff = BPF_CORE_READ(skb, mac_header);
    __u16 thoff = BPF_CORE_READ(skb, transport_header);
    
    // 获取数据包头部指针
    unsigned char *head = BPF_CORE_READ(skb, head);
    
    // 解析以太网头部
    struct ethhdr *eth = 0;
    if (head && mhoff >= 0) {
        eth = (struct ethhdr *)(head + mhoff);
        // 注意：实际使用中需要使用 bpf_probe_read_kernel 安全读取
        // ...处理 MAC 地址等以太网信息
    }
    
    // 解析 IP 头部
    struct iphdr *iph = 0;
    if (head && nhoff >= 0) {
        iph = (struct iphdr *)(head + nhoff);
        // 注意：实际使用中需要使用 bpf_probe_read_kernel 安全读取
        // ...处理 IP 地址等网络层信息
    }
    
    // 解析传输层头部（TCP/UDP）
    // ...
}
```

## 6. 实际应用场景

在 netbee 项目中，通过分析 `struct pt_regs *ctx` 参数获取的信息，可以实现多种网络监控和安全功能：

1. **网络流量监控**：通过提取 skb 信息，监控网络流量的来源、目标和协议类型
2. **防火墙策略审计**：跟踪 ipt_do_table 和 nf_hook_slow 的调用，审计防火墙规则的应用情况
3. **异常流量检测**：分析数据包内容和处理流程，识别潜在的网络攻击和异常行为
4. **性能分析**：统计 Netfilter 钩子点的处理时间和调用频率，进行性能优化

## 7. 总结

`struct pt_regs *ctx` 参数是 eBPF kprobe 程序中获取内核函数执行上下文的关键。通过本文的分析，我们了解了：

1. pt_regs 的基本结构和在 eBPF 中的访问方式
2. 如何从 ctx 中提取 nf_hook_slow 函数的各个参数
3. 如何推断并提取 ipt_do_table 函数的参数
4. 如何进一步访问和分析网络数据包信息
5. 这些技术在网络监控和安全领域的应用场景

通过灵活运用这些知识，我们可以开发出功能强大的 eBPF 程序，实现对 Linux 内核网络行为的深度监控和分析。