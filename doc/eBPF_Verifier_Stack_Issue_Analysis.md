# eBPF验证器栈内存访问问题分析与修复

## 问题概述

在eBPF程序开发过程中，遇到了验证器错误：`invalid indirect read from stack R3 off -32+4 size 24`，导致程序无法加载到内核中。

## 错误信息

```
2025/10/07 16:23:18 Verifier error: load program: permission denied:
        Unrecognized arg#0 type PTR
        ; int handle_nf_hook_slow(struct pt_regs *ctx)
        0: (bf) r8 = r1
        1: (b7) r1 = 774778489
        ; bpf_printk("handle_nf_hook_slow entry...");
        2: (63) *(u32 *)(r10 -72) = r1
        3: (18) r1 = 0x72746e6520776f6c
        5: (7b) *(u64 *)(r10 -80) = r1
        6: (18) r1 = 0x735f6b6f6f685f66
        8: (7b) *(u64 *)(r10 -88) = r1
        9: (18) r1 = 0x6e5f656c646e6168
        11: (7b) *(u64 *)(r10 -96) = r1
        12: (b7) r6 = 0
        13: (73) *(u8 *)(r10 -68) = r6
        last_idx 13 first_idx 0
        regs=40 stack=0 before 12: (b7) r6 = 0
        14: (bf) r1 = r10
        ;
        15: (07) r1 += -96
        ; bpf_printk("handle_nf_hook_slow entry...");
        16: (b7) r2 = 29
        17: (85) call bpf_trace_printk#6
        last_idx 17 first_idx 0
        regs=4 stack=0 before 16: (b7) r2 = 29
        ; struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx); // 数据包指针
        18: (79) r7 = *(u64 *)(r8 +112)
        ; struct nf_hook_state *nf_state = (struct nf_hook_state *)PT_REGS_PARM2(ctx); // 钩子状态
        19: (79) r3 = *(u64 *)(r8 +104)
        ; if (nf_state) {
        20: (15) if r3 == 0x0 goto pc+33
         R0_w=inv(id=0) R3_w=inv(id=0) R6_w=invP0 R7_w=inv(id=0) R8_w=ctx(id=0,off=0,imm=0) R10=fp0 fp-72=???mmmmm fp-80_w=mmmmmmmm fp-88_w=mmmmmmmm fp-96_w=mmmmmmmm
        21: (b7) r1 = 0
        22: (0f) r3 += r1
        23: (bf) r1 = r10
        ;
        24: (07) r1 += -96
        ; hook = BPF_CORE_READ(nf_state, hook);
        25: (b7) r2 = 4
        26: (85) call bpf_probe_read_kernel#113
        last_idx 26 first_idx 0
        regs=4 stack=0 before 25: (b7) r2 = 4
        ; hook = BPF_CORE_READ(nf_state, hook);
        27: (61) r6 = *(u32 *)(r10 -96)
        ; if (hook > 4) {
        28: (a5) if r6 < 0x5 goto pc+25

        from 28 to 54: R0=inv(id=0) R6_w=inv(id=0,umax_value=4,var_off=(0x0; 0x7)) R7=inv(id=0) R8=ctx(id=0,off=0,imm=0) R10=fp0 fp-72=???mmmmm fp-80=mmmmmmmm fp-88=mmmmmmmm fp-96=mmmmmmmm
        ; __u64 pid_tgid = bpf_get_current_pid_tgid();
        54: (85) call bpf_get_current_pid_tgid#14
        55: (bf) r8 = r0
        ; __u32 pid = (__u32)(pid_tgid >> 32);
        56: (bf) r1 = r8
        57: (77) r1 >>= 32
        ; return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
        58: (67) r8 <<= 16
        ; return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
        59: (af) r8 ^= r1
        ; return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
        60: (85) call bpf_get_smp_processor_id#8
        ; return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
        61: (67) r0 <<= 8
        ; return pid ^ (tid << 16) ^ (bpf_get_smp_processor_id() << 8);
        62: (af) r8 ^= r0
        ; __u32 key = generate_nf_hook_key();
        63: (63) *(u32 *)(r10 -4) = r8
        ; struct nf_hook_slow_state state = {
        64: (7b) *(u64 *)(r10 -24) = r7
        65: (63) *(u32 *)(r10 -32) = r6
        ; .start_ns = bpf_ktime_get_ns(),  // 仅用于调试
        66: (85) call bpf_ktime_get_ns#5
        ; struct nf_hook_slow_state state = {
        67: (7b) *(u64 *)(r10 -16) = r0
        68: (bf) r2 = r10
        ; __u64 pid_tgid = bpf_get_current_pid_tgid();
        69: (07) r2 += -4
        70: (bf) r3 = r10
        71: (07) r3 += -32
        72: (b7) r8 = 0
        ; int ret = bpf_map_update_elem(&nf_hook_slow_states, &key, &state, BPF_ANY);
        73: (18) r1 = 0xffff907429d63400
        75: (b7) r4 = 0
        76: (85) call bpf_map_update_elem#2
        invalid indirect read from stack R3 off -32+4 size 24
        processed 70 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 2 mark_read 2
2025/10/07 16:23:18 Failed to load eBPF collection: program handle_nf_hook_slow: load program: permission denied: invalid indirect read from stack R3 off -32+4 size 24 (83 line(s) omitted)
```

## 问题分析

### 1. 错误位置
错误发生在第727行的`bpf_map_update_elem`调用：
```c
int ret = bpf_map_update_elem(&nf_hook_slow_states, &key, &state, BPF_ANY);
```

### 2. 问题代码
```c
// 有问题的代码
struct nf_hook_slow_state state = {
    .hook = hook,           // 存储在 r10-32 (4字节)
    .skb = skb,            // 存储在 r10-24 (8字节) 
    .start_ns = bpf_ktime_get_ns(),  // 存储在 r10-16 (8字节)
};
```

### 3. 结构体定义
```c
struct nf_hook_slow_state {
    unsigned int hook;        // 4字节
    struct sk_buff *skb;      // 8字节  
    __u64 start_ns;          // 8字节
};
```

### 4. 栈内存布局分析

| 栈偏移 | 内容 | 大小 | 状态 |
|--------|------|------|------|
| r10-32 | hook字段 | 4字节 | 已初始化 |
| r10-28 | 填充区域 | 4字节 | **未初始化** |
| r10-24 | skb指针 | 8字节 | 已初始化 |
| r10-16 | start_ns | 8字节 | 已初始化 |
| r10-8  | 其他数据 | 8字节 | 其他用途 |

### 5. 验证器检查失败原因

1. **内存布局不连续：** 结构体字段之间存在填充区域
2. **验证器无法确定填充区域内容：** `r10-32+4`（即`r10-28`）位置的数据状态不明确
3. **安全限制：** eBPF验证器拒绝访问可能包含未初始化数据的内存区域

## 修复方案

### 方案1：使用__builtin_memset初始化（推荐）

**修复代码：**
```c
// 修复后的代码
struct nf_hook_slow_state state;
__builtin_memset(&state, 0, sizeof(state));  // 初始化整个结构体
state.hook = hook;
state.skb = skb;
state.start_ns = bpf_ktime_get_ns();
```

**优点：**
- 简单有效，一行代码解决问题
- `__builtin_memset`是eBPF验证器明确支持的函数
- 确保所有内存区域都被明确初始化
- 性能影响很小

### 方案2：使用packed结构体

```c
struct __attribute__((packed)) nf_hook_slow_state {
    unsigned int hook;
    struct sk_buff *skb;
    __u64 start_ns;
};
```

**优点：**
- 消除结构体填充
- 内存布局紧凑

**缺点：**
- 可能影响性能（非对齐访问）
- 需要修改结构体定义

### 方案3：手动初始化每个字段

```c
struct nf_hook_slow_state state;
state.hook = 0;
state.skb = NULL;
state.start_ns = 0;
// 然后设置实际值
state.hook = hook;
state.skb = skb;
state.start_ns = bpf_ktime_get_ns();
```

**优点：**
- 明确控制每个字段的初始化
- 不需要额外的函数调用

**缺点：**
- 代码冗长
- 容易遗漏字段

### 方案4：分别存储字段

```c
// 不存储整个结构体，而是分别存储各个字段
bpf_map_update_elem(&hook_map, &key, &hook, BPF_ANY);
bpf_map_update_elem(&skb_map, &key, &skb, BPF_ANY);
bpf_map_update_elem(&timestamp_map, &key, &start_ns, BPF_ANY);
```

**优点：**
- 避免结构体布局问题
- 更灵活的数据管理

**缺点：**
- 需要多个map
- 增加复杂性

## 最终采用的修复方案

我们采用了**方案1**，使用`__builtin_memset`初始化整个结构体：

```c
// 创建简化的状态结构体
struct nf_hook_slow_state state;
__builtin_memset(&state, 0, sizeof(state));  // 初始化整个结构体
state.hook = hook;
state.skb = skb;
state.start_ns = bpf_ktime_get_ns();  // 仅用于调试
```

## 验证器错误信息解读

- `invalid indirect read from stack`：无效的栈间接读取
- `R3 off -32+4`：寄存器R3指向栈偏移-32+4的位置（即-28）
- `size 24`：尝试读取24字节
- 验证器无法确认`r10-28`位置的数据安全性

## 预防措施

1. **总是初始化结构体：** 使用`__builtin_memset`或手动初始化
2. **避免结构体填充：** 考虑使用`__attribute__((packed))`
3. **测试不同内核版本：** eBPF验证器行为可能因内核版本而异
4. **使用静态分析工具：** 提前发现潜在问题

## 相关资源

- [eBPF验证器文档](https://docs.kernel.org/6.14/bpf/verifier.html)
- [eBPF程序开发指南](https://docs.kernel.org/6.14/bpf/bpf_design_QA.html)
- [内核版本：5.10.134-19.1.an8.x86_64]

## 总结

这个问题的根本原因是eBPF验证器对栈内存安全性的严格检查。通过使用`__builtin_memset`初始化整个结构体，我们确保了验证器能够确认所有内存区域都是安全可读的，从而解决了验证器错误。这种修复方式简单、有效，且对性能影响最小。
