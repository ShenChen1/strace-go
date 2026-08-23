#ifndef STRACE_GO_ENTER_RUNTIME_H
#define STRACE_GO_ENTER_RUNTIME_H

#define ENTER_PROLOGUE(ctx)                                                \
    u32 sys_id = (u32)(ctx)->id;                                           \
    u64 pid_tgid = bpf_get_current_pid_tgid();                              \
    u32 tid = (u32)pid_tgid;                                                \
    u32 pid = (u32)(pid_tgid >> 32);                                        \
    u64 enter_time = bpf_ktime_get_ns();                                   \
    u32 cfg_key = 0;                                                       \
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);                 \
    volatile s32 stack_id = -1;                                           \
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {                            \
        stack_id = bpf_get_stackid((void *)(ctx), &stack_traces, BPF_F_USER_STACK); \
    }

// Tail-call failure owns the bounded event and pending state outside the dispatcher.
static __always_inline void emit_enter_dispatch_fallback(
    struct trace_event_raw_sys_enter *ctx,
    u32 pid,
    u32 tid,
    u32 *cfg)
{
    u32 sys_id = (u32)ctx->id;
    u64 enter_time = bpf_ktime_get_ns();
    volatile s32 stack_id = -1;
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    emit_plain_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
}

#endif
