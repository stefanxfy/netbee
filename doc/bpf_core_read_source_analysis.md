# BPF CO-RE Read 源码深度解析

## 1. 概述

`bpf_core_read.h` 是 libbpf 库中实现 BPF CO-RE (Compile Once - Run Everywhere) 功能的核心头文件。它通过编译器内置函数和宏定义，提供了一套完整的可重定位内存读取机制，使得 eBPF 程序能够在不同内核版本间移植。

### 1.1 设计目标

- **一次编译，到处运行**：解决不同内核版本结构体字段偏移不一致的问题
- **类型安全**：利用 BTF (BPF Type Format) 信息进行类型验证
- **性能优化**：通过编译时重定位避免运行时开销
- **易用性**：提供简洁的宏接口隐藏复杂实现

## 2. 核心枚举类型

### 2.1 字段信息类型 (bpf_field_info_kind)

```c
enum bpf_field_info_kind {
    BPF_FIELD_BYTE_OFFSET = 0,  // 字段字节偏移量
    BPF_FIELD_BYTE_SIZE = 1,    // 字段字节大小
    BPF_FIELD_EXISTS = 2,       // 字段是否存在于目标内核
    BPF_FIELD_SIGNED = 3,       // 字段是否有符号
    BPF_FIELD_LSHIFT_U64 = 4,   // 位字段左移量
    BPF_FIELD_RSHIFT_U64 = 5,   // 位字段右移量
};
```

**设计思想**：
- 通过枚举定义字段的各种元数据类型
- 配合 `__builtin_preserve_field_info()` 内置函数使用
- 编译器根据 BTF 信息生成重定位记录
- libbpf 在加载时根据目标内核 BTF 调整偏移量

**应用场景**：
```c
// 获取字段偏移量
__u32 offset = __builtin_preserve_field_info(ptr->field, BPF_FIELD_BYTE_OFFSET);

// 检查字段是否存在
if (__builtin_preserve_field_info(ptr->field, BPF_FIELD_EXISTS)) {
    // 字段存在，可以安全访问
}
```

### 2.2 类型 ID 类型 (bpf_type_id_kind)

```c
enum bpf_type_id_kind {
    BPF_TYPE_ID_LOCAL = 0,   // 本地程序的 BTF 类型 ID
    BPF_TYPE_ID_TARGET = 1,  // 目标内核的 BTF 类型 ID
};
```

**设计思想**：
- 区分本地 BTF 和目标内核 BTF
- 支持类型匹配和验证
- 用于 `__builtin_btf_type_id()` 内置函数

### 2.3 类型信息类型 (bpf_type_info_kind)

```c
enum bpf_type_info_kind {
    BPF_TYPE_EXISTS = 0,  // 类型是否存在于目标内核
    BPF_TYPE_SIZE = 1,    // 类型在目标内核中的大小
};
```

### 2.4 枚举值类型 (bpf_enum_value_kind)

```c
enum bpf_enum_value_kind {
    BPF_ENUMVAL_EXISTS = 0,  // 枚举值是否存在
    BPF_ENUMVAL_VALUE = 1,   // 枚举值的实际值
};
```

## 3. 核心宏定义

### 3.1 基础重定位宏

```c
#define __CORE_RELO(src, field, info) \
    __builtin_preserve_field_info((src)->field, BPF_FIELD_##info)
```

**设计思想**：
- 封装编译器内置函数 `__builtin_preserve_field_info()`
- 自动拼接枚举常量名（通过 `BPF_FIELD_##info`）
- 简化字段元数据获取操作

**使用示例**：
```c
// 等价于 __builtin_preserve_field_info(ptr->member, BPF_FIELD_BYTE_OFFSET)
__u32 offset = __CORE_RELO(ptr, member, BYTE_OFFSET);
```

## 4. 位字段读取机制

### 4.1 位字段探测读取宏

```c
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __CORE_BITFIELD_PROBE_READ(dst, src, fld) \
    bpf_probe_read_kernel( \
        (void *)dst, \
        __CORE_RELO(src, fld, BYTE_SIZE), \
        (const void *)src + __CORE_RELO(src, fld, BYTE_OFFSET))
#else
// 大端序需要调整目标指针
#define __CORE_BITFIELD_PROBE_READ(dst, src, fld) \
    bpf_probe_read_kernel( \
        (void *)dst + (8 - __CORE_RELO(src, fld, BYTE_SIZE)), \
        __CORE_RELO(src, fld, BYTE_SIZE), \
        (const void *)src + __CORE_RELO(src, fld, BYTE_OFFSET))
#endif
```

**设计思想**：
- 处理不同字节序的位字段读取
- 小端序：直接读取到 `dst` 的低位字节
- 大端序：需要调整目标指针，使数据对齐到高位字节
- 使用 CO-RE 重定位获取字段偏移和大小

### 4.2 位字段值提取 (探测模式)

```c
#define BPF_CORE_READ_BITFIELD_PROBED(s, field) ({ \
    unsigned long long val = 0; \
    \
    __CORE_BITFIELD_PROBE_READ(&val, s, field); \
    val <<= __CORE_RELO(s, field, LSHIFT_U64); \
    if (__CORE_RELO(s, field, SIGNED)) \
        val = ((long long)val) >> __CORE_RELO(s, field, RSHIFT_U64); \
    else \
        val = val >> __CORE_RELO(s, field, RSHIFT_U64); \
    val; \
})
```

**核心算法**：
1. 初始化 64 位变量为 0
2. 使用 `bpf_probe_read_kernel()` 读取底层整数存储
3. 左移对齐位字段到最高位
4. 根据符号性质进行右移（算术右移或逻辑右移）
5. 返回提取的位字段值

**示例场景**：
```c
struct example {
    unsigned int a:5;  // 5位无符号位字段
    int b:11;          // 11位有符号位字段
};

struct example *e;
unsigned int val_a = BPF_CORE_READ_BITFIELD_PROBED(e, a);
int val_b = BPF_CORE_READ_BITFIELD_PROBED(e, b);
```

### 4.3 位字段值提取 (直接模式)

```c
#define BPF_CORE_READ_BITFIELD(s, field) ({ \
    const void *p = (const void *)s + __CORE_RELO(s, field, BYTE_OFFSET); \
    unsigned long long val; \
    \
    asm volatile("" : "=r"(p) : "0"(p)); \
    \
    switch (__CORE_RELO(s, field, BYTE_SIZE)) { \
    case 1: val = *(const unsigned char *)p; break; \
    case 2: val = *(const unsigned short *)p; break; \
    case 4: val = *(const unsigned int *)p; break; \
    case 8: val = *(const unsigned long long *)p; break; \
    } \
    val <<= __CORE_RELO(s, field, LSHIFT_U64); \
    if (__CORE_RELO(s, field, SIGNED)) \
        val = ((long long)val) >> __CORE_RELO(s, field, RSHIFT_U64); \
    else \
        val = val >> __CORE_RELO(s, field, RSHIFT_U64); \
    val; \
})
```

**设计亮点**：
- **Barrier Var 技巧**：`asm volatile("" : "=r"(p) : "0"(p))` 
  - 防止编译器优化导致重复重定位
  - 强制编译器将指针视为"黑盒"
  - 确保 `BYTE_OFFSET` 重定位只计算一次

- **Switch 优化**：根据字段大小选择最优读取方式
  - 避免 4 次独立的内存读取操作
  - 利用编译时常量折叠优化

**适用场景**：
- 类型化的原始跟踪点 (typed raw tracepoints)
- 支持直接内存访问的 BPF 程序类型

## 5. 便捷性宏

### 5.1 字段存在性检查

```c
#if !__has_builtin(__builtin_preserve_field_info)
#warning "LLVM does not support __builtin_preserve_field_info - CO-RE will not work!"
#define bpf_core_field_exists(field) (0)
#else
#define bpf_core_field_exists(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_EXISTS)
#endif
```

**设计思想**：
- 编译时检查 LLVM 是否支持 CO-RE
- 不支持时返回 0 并发出警告
- 支持时动态检测字段在目标内核中是否存在

**使用场景**：
```c
// 兼容不同内核版本的代码
if (bpf_core_field_exists(task->mm->rss_stat)) {
    // 新内核路径
} else {
    // 旧内核回退路径
}
```

### 5.2 字段大小获取

```c
#define bpf_core_field_size(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_BYTE_SIZE)
```

### 5.3 类型 ID 获取

```c
// 本地 BTF 类型 ID
#define bpf_core_type_id_local(type) \
    __builtin_btf_type_id(*(typeof(type) *)0, BPF_TYPE_ID_LOCAL)

// 目标内核 BTF 类型 ID
#define bpf_core_type_id_kernel(type) \
    __builtin_btf_type_id(*(typeof(type) *)0, BPF_TYPE_ID_TARGET)
```

**技巧说明**：
- `*(typeof(type) *)0`：创建类型为 `type` 的空指针并解引用
- 仅用于类型推导，不会实际访问地址 0
- 编译器在编译时处理，不产生运行时代码

### 5.4 类型存在性和大小

```c
// 类型是否存在
#define bpf_core_type_exists(type) \
    __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_EXISTS)

// 类型大小
#define bpf_core_type_size(type) \
    __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_SIZE)
```

### 5.5 枚举值处理

```c
// 枚举值是否存在
#define bpf_core_enum_value_exists(enum_type, enum_value) \
    __builtin_preserve_enum_value(*(typeof(enum_type) *)enum_value, BPF_ENUMVAL_EXISTS)

// 枚举值的实际值
#define bpf_core_enum_value(enum_type, enum_value) \
    __builtin_preserve_enum_value(*(typeof(enum_type) *)enum_value, BPF_ENUMVAL_VALUE)
```

## 6. 核心读取宏

### 6.1 基础读取宏

```c
// 内核空间读取
#define bpf_core_read(dst, sz, src) \
    bpf_probe_read_kernel(dst, sz, (const void *)__builtin_preserve_access_index(src))

// 用户空间读取
#define bpf_core_read_user(dst, sz, src) \
    bpf_probe_read_user(dst, sz, (const void *)__builtin_preserve_access_index(src))

// 字符串读取
#define bpf_core_read_str(dst, sz, src) \
    bpf_probe_read_kernel_str(dst, sz, (const void *)__builtin_preserve_access_index(src))

#define bpf_core_read_user_str(dst, sz, src) \
    bpf_probe_read_user_str(dst, sz, (const void *)__builtin_preserve_access_index(src))
```

**关键函数**：`__builtin_preserve_access_index()`
- 捕获字段访问表达式
- 生成 BTF 重定位记录
- 记录结构体类型 ID 和字段访问路径
- libbpf 根据目标内核 BTF 调整实际偏移

## 7. 变参宏系统

### 7.1 参数计数宏

```c
#define ___concat(a, b) a ## b
#define ___apply(fn, n) ___concat(fn, n)
#define ___nth(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, __11, N, ...) N

// 返回参数个数
#define ___narg(...) ___nth(_, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

// 返回是否有参数 (0 或 N)
#define ___empty(...) ___nth(_, ##__VA_ARGS__, N, N, N, N, N, N, N, N, N, N, 0)
```

**工作原理**：
- `___nth` 宏选择第 12 个参数
- 当传入 N 个参数时，第 12 个参数对应位置的值就是 N
- `##__VA_ARGS__` 处理空参数情况（GNU 扩展）

**示例**：
```c
___narg(a, b, c)          // 展开为 3
___narg(a)                // 展开为 1
___narg()                 // 展开为 0
```

### 7.2 参数操作宏

```c
// 获取最后一个参数
#define ___last1(x) x
#define ___last2(a, x) x
#define ___last3(a, b, x) x
// ... 最多支持 10 个参数
#define ___last(...) ___apply(___last, ___narg(__VA_ARGS__))(__VA_ARGS__)

// 获取除最后一个参数外的所有参数
#define ___nolast2(a, _) a
#define ___nolast3(a, b, _) a, b
// ... 最多支持 10 个参数
#define ___nolast(...) ___apply(___nolast, ___narg(__VA_ARGS__))(__VA_ARGS__)
```

**设计模式**：
1. 定义不同参数数量的版本（1-10）
2. 使用 `___narg` 计算参数个数
3. 使用 `___apply` 选择对应版本
4. 实现可变参数宏的分支逻辑

### 7.3 箭头操作符生成

```c
#define ___arrow1(a) a
#define ___arrow2(a, b) a->b
#define ___arrow3(a, b, c) a->b->c
#define ___arrow4(a, b, c, d) a->b->c->d
// ... 最多支持 10 级
#define ___arrow(...) ___apply(___arrow, ___narg(__VA_ARGS__))(__VA_ARGS__)

// 获取表达式类型
#define ___type(...) typeof(___arrow(__VA_ARGS__))
```

**用途**：
- 将逗号分隔的字段列表转换为箭头表达式
- `___arrow(s, a, b, c)` → `s->a->b->c`
- `___type(s, a, b)` → `typeof(s->a->b)`

## 8. 递归读取机制

### 8.1 单次读取宏

```c
#define ___read(read_fn, dst, src_type, src, accessor) \
    read_fn((void *)(dst), sizeof(*(dst)), &((src_type)(src))->accessor)
```

**参数说明**：
- `read_fn`：读取函数（如 `bpf_core_read`）
- `dst`：目标缓冲区
- `src_type`：源类型（用于类型转换）
- `src`：源指针
- `accessor`：字段访问路径

### 8.2 指针链式读取

```c
// 读取第一个指针
#define ___rd_first(fn, src, a) ___read(fn, &__t, ___type(src), src, a);

// 读取最后一个指针
#define ___rd_last(fn, ...) \
    ___read(fn, &__t, ___type(___nolast(__VA_ARGS__)), __t, ___last(__VA_ARGS__));

// 1 级指针
#define ___rd_p1(fn, ...) const void *__t; ___rd_first(fn, __VA_ARGS__)

// 2 级指针
#define ___rd_p2(fn, ...) ___rd_p1(fn, ___nolast(__VA_ARGS__)) ___rd_last(fn, __VA_ARGS__)

// 3-9 级指针类似...

// 统一入口
#define ___read_ptrs(fn, src, ...) \
    ___apply(___rd_p, ___narg(__VA_ARGS__))(fn, src, __VA_ARGS__)
```

**递归展开示例**：
```c
// 调用：___read_ptrs(bpf_core_read, task, mm, pgd, pgd_val)
// 展开为：
const void *__t;
bpf_core_read(&__t, sizeof(__t), &task->mm);           // 第1级
bpf_core_read(&__t, sizeof(__t), &__t->pgd);           // 第2级
bpf_core_read(&__t, sizeof(__t), &__t->pgd_val);       // 第3级
```

### 8.3 核心读取逻辑

```c
// 0 级：直接读取
#define ___core_read0(fn, fn_ptr, dst, src, a) \
    ___read(fn, dst, ___type(src), src, a);

// N 级：先读取中间指针，再读取最终值
#define ___core_readN(fn, fn_ptr, dst, src, ...) \
    ___read_ptrs(fn_ptr, src, ___nolast(__VA_ARGS__)) \
    ___read(fn, dst, ___type(src, ___nolast(__VA_ARGS__)), __t, \
        ___last(__VA_ARGS__));

// 自动选择
#define ___core_read(fn, fn_ptr, dst, src, a, ...) \
    ___apply(___core_read, ___empty(__VA_ARGS__))(fn, fn_ptr, dst, \
                          src, a, ##__VA_ARGS__)
```

**分支逻辑**：
- 如果没有额外参数（`__VA_ARGS__` 为空），使用 `___core_read0`
- 如果有额外参数，使用 `___core_readN`

## 9. 高级读取宏

### 9.1 BPF_CORE_READ_INTO

```c
#define BPF_CORE_READ_INTO(dst, src, a, ...) ({ \
    ___core_read(bpf_core_read, bpf_core_read, \
             dst, (src), a, ##__VA_ARGS__) \
})
```

**使用示例**：
```c
struct task_struct *task;
pid_t pid;

// 读取 task->tgid
BPF_CORE_READ_INTO(&pid, task, tgid);

// 读取 task->mm->start_code
unsigned long start_code;
BPF_CORE_READ_INTO(&start_code, task, mm, start_code);
```

**展开过程**：
```c
// BPF_CORE_READ_INTO(&start_code, task, mm, start_code)
// 展开为：
const void *__t;
bpf_core_read(&__t, sizeof(__t), &task->mm);
bpf_core_read(&start_code, sizeof(start_code), &__t->start_code);
```

### 9.2 BPF_CORE_READ

```c
#define BPF_CORE_READ(src, a, ...) ({ \
    ___type((src), a, ##__VA_ARGS__) __r; \
    BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__); \
    __r; \
})
```

**设计优势**：
- 自动推导返回值类型
- 支持链式指针访问
- 代码简洁，类似普通 C 语言访问

**使用示例**：
```c
struct task_struct *task;

// 等价于：task->mm->start_code
unsigned long start_code = BPF_CORE_READ(task, mm, start_code);

// 等价于：task->cred->uid.val
uid_t uid = BPF_CORE_READ(task, cred, uid, val);

// 等价于：task->mm->arg_start
unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
```

### 9.3 字符串读取宏

```c
#define BPF_CORE_READ_STR_INTO(dst, src, a, ...) ({ \
    ___core_read(bpf_core_read_str, bpf_core_read, \
             dst, (src), a, ##__VA_ARGS__) \
})
```

**特点**：
- 中间指针使用 `bpf_core_read` 读取
- 最终字符串使用 `bpf_core_read_str` 读取
- 自动处理空指针和字符串截断

**使用示例**：
```c
struct task_struct *task;
char comm[16];

// 读取进程名称：task->comm
BPF_CORE_READ_STR_INTO(comm, task, comm);

// 读取可执行文件路径：task->mm->exe_file->f_path.dentry->d_name.name
char filename[256];
BPF_CORE_READ_STR_INTO(filename, task, mm, exe_file, f_path, dentry, d_name, name);
```

### 9.4 用户空间读取宏

```c
// 用户空间版本
#define BPF_CORE_READ_USER_INTO(dst, src, a, ...) ({ \
    ___core_read(bpf_core_read_user, bpf_core_read_user, \
             dst, (src), a, ##__VA_ARGS__) \
})

#define BPF_CORE_READ_USER(src, a, ...) ({ \
    ___type((src), a, ##__VA_ARGS__) __r; \
    BPF_CORE_READ_USER_INTO(&__r, (src), a, ##__VA_ARGS__); \
    __r; \
})
```

**注意事项**：
- 源类型必须是内核类型，存在于内核 BTF 中
- 典型场景：读取系统调用参数中的用户空间数据
- 不支持自定义用户类型的 CO-RE 重定位

### 9.5 非 CO-RE 变体

```c
// 不使用 CO-RE 重定位的版本
#define BPF_PROBE_READ_INTO(dst, src, a, ...) ({ \
    ___core_read(bpf_probe_read, bpf_probe_read, \
             dst, (src), a, ##__VA_ARGS__) \
})

#define BPF_PROBE_READ(src, a, ...) ({ \
    ___type((src), a, ##__VA_ARGS__) __r; \
    BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__); \
    __r; \
})
```

**使用场景**：
- 不需要跨内核版本移植
- 访问已知固定偏移的结构体
- 调试和测试目的

## 10. 设计模式总结

### 10.1 宏编程技巧

1. **参数计数技巧**：利用 `___nth` 宏选择性返回参数
2. **递归宏展开**：通过参数数量选择不同版本的宏
3. **类型推导**：使用 `typeof` 和空指针技巧获取类型
4. **Barrier Var**：使用内联汇编防止编译器过度优化
5. **表达式语句**：使用 `({...})` GNU 扩展返回值

### 10.2 编译器协作

```
源代码 (BPF_CORE_READ)
    ↓
编译器内置函数 (__builtin_preserve_*)
    ↓
BTF 重定位记录
    ↓
libbpf 加载器
    ↓
根据目标内核 BTF 调整偏移
    ↓
可执行的 eBPF 字节码
```

### 10.3 性能优化策略

1. **编译时计算**：尽可能在编译时完成类型和偏移计算
2. **减少探测次数**：使用临时变量 `__t` 缓存中间结果
3. **避免重复重定位**：使用 barrier_var 确保重定位只执行一次
4. **内联优化**：所有宏都会被内联，无函数调用开销

### 10.4 错误处理

- 大多数宏返回 `bpf_probe_read_*()` 的返回值
- 成功返回 0，失败返回负数
- 调用方可以检查返回值并处理错误

```c
int ret = BPF_CORE_READ_INTO(&value, task, field);
if (ret < 0) {
    // 处理读取失败
}
```

## 11. 实际应用示例

### 11.1 读取进程信息

```c
SEC("kprobe/sys_execve")
int trace_execve(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 读取进程 PID
    pid_t pid = BPF_CORE_READ(task, tgid);
    
    // 读取父进程 PID
    pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    // 读取进程名称
    char comm[16];
    BPF_CORE_READ_STR_INTO(comm, task, comm);
    
    // 读取用户 ID
    uid_t uid = BPF_CORE_READ(task, real_cred, uid, val);
    
    bpf_printk("execve: pid=%d ppid=%d comm=%s uid=%d", pid, ppid, comm, uid);
    return 0;
}
```

### 11.2 网络包分析

```c
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    // 读取源地址和端口
    __u32 saddr = BPF_CORE_READ(sk, __sk_common, skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common, skc_num);
    
    // 读取目标地址和端口
    __u32 daddr = BPF_CORE_READ(sk, __sk_common, skc_daddr);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common, skc_dport));
    
    bpf_printk("TCP connect: %pI4:%d -> %pI4:%d", &saddr, sport, &daddr, dport);
    return 0;
}
```

### 11.3 兼容性检查

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查字段是否存在（不同内核版本）
    if (bpf_core_field_exists(task->mm->rss_stat)) {
        // 新内核：使用 rss_stat
        long rss = BPF_CORE_READ(task, mm, rss_stat, count[MM_FILEPAGES]);
        bpf_printk("RSS pages: %ld", rss);
    } else {
        // 旧内核：回退方案
        bpf_printk("RSS stat not available on this kernel");
    }
    
    return 0;
}
```

## 12. 优势与限制

### 12.1 优势

1. **跨内核兼容**：一次编译可在不同内核版本运行
2. **类型安全**：编译时类型检查，运行时重定位验证
3. **性能高效**：无运行时开销，重定位在加载时完成
4. **易于使用**：宏接口简洁，类似普通 C 语言访问
5. **自动适配**：自动处理结构体布局变化

### 12.2 限制

1. **LLVM 依赖**：需要支持 BTF 和 CO-RE 的 LLVM 版本（≥10）
2. **内核要求**：目标内核需要支持 BTF（≥5.2）
3. **字段访问深度**：最多支持 9 级指针链式访问
4. **用户类型限制**：用户空间读取仍需内核类型定义

### 12.3 最佳实践

1. **优先使用 CO-RE**：除非有特殊原因，否则使用 CO-RE 版本
2. **检查字段存在性**：在访问可能不存在的字段前检查
3. **错误处理**：检查读取操作的返回值
4. **避免深层嵌套**：过深的指针链式访问影响可读性
5. **使用 BTF 类型**：确保访问的类型在 vmlinux.h 中定义

## 13. 总结

`bpf_core_read.h` 是 eBPF 可移植性的基石，通过巧妙的宏编程技巧和编译器内置函数协作，提供了一套优雅的解决方案来处理内核结构体偏移的跨版本兼容问题。

**核心理念**：
- 编译时：记录类型信息和访问路径（BTF 重定位）
- 加载时：根据目标内核调整偏移量（libbpf）
- 运行时：无额外开销，直接访问正确地址

**技术精髓**：
- 递归宏展开实现可变参数处理
- 编译器内置函数生成 BTF 重定位记录
- 类型推导和类型安全保证正确性
- 优化技巧确保零运行时开销

这套机制使得 eBPF 程序真正实现了"一次编译，到处运行"的目标，极大地降低了 eBPF 开发和部署的复杂度。

