#ifndef STRACE_GO_NATIVE_TASK_ABI_H
#define STRACE_GO_NATIVE_TASK_ABI_H

/* Kernel thread flags describe the current syscall ABI, including int80
 * from a 64-bit x86 executable. ELF class alone cannot detect that case. */
#if defined(__TARGET_ARCH_x86)
#define NATIVE_X86_TS_COMPAT 0x0002U
#define NATIVE_X86_X32_SYSCALL_BIT 0x40000000U
static __always_inline int current_syscall_has_native_abi(u32 sys_id)
{
    if (sys_id & NATIVE_X86_X32_SYSCALL_BIT) return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    u32 status = 0;
    if (BPF_CORE_READ_INTO(&status, task, thread_info.status) < 0) return 0;
    return !(status & NATIVE_X86_TS_COMPAT);
}

static __always_inline s64 native_kretprobe_return(struct pt_regs *ctx)
{
    return (s64)BPF_CORE_READ(ctx, ax);
}
#elif defined(__TARGET_ARCH_arm64)
#define NATIVE_ARM64_TIF_32BIT (1UL << 22)
struct pt_regs___strace_go_arm64 {
    u64 regs[31];
} __attribute__((preserve_access_index));

static __always_inline int current_syscall_has_native_abi(u32 sys_id)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    unsigned long flags = 0;
    if (BPF_CORE_READ_INTO(&flags, task, thread_info.flags) < 0) return 0;
    return !(flags & NATIVE_ARM64_TIF_32BIT);
}

static __always_inline s64 native_kretprobe_return(struct pt_regs *ctx)
{
    return (s64)BPF_CORE_READ((struct pt_regs___strace_go_arm64 *)ctx, regs[0]);
}
#else
#error "unsupported architecture: native amd64 or arm64 required"
#endif

#endif
