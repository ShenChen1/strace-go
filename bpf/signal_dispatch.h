#ifndef STRACE_GO_SIGNAL_DISPATCH_H
#define STRACE_GO_SIGNAL_DISPATCH_H

#define SIGNAL_CODE_USER 0
#define SIGNAL_CODE_QUEUE -1
#define SIGNAL_CODE_TKILL -6
#define SIGNAL_NUMBER_CHLD 17

static __always_inline s32 target_pending_stack_id(u32 tid)
{
    s32 *stack_id = bpf_map_lookup_elem(&pending_stack_map, &tid);
    if (!stack_id) {
        return -1;
    }
    return *stack_id;
}

static __always_inline int populate_signal_event_v2(
    struct bpf_raw_tracepoint_args *ctx,
    unsigned long info_address,
    u32 signo,
    u32 config,
    struct signal_event_v2 *body)
{
    if (info_address <= 1) {
        return -1;
    }
    body->signo = signo;
    body->stack_id = -1;
    if (config & CONFIG_CAPTURE_STACK) {
        body->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    struct kernel_siginfo *info = (void *)info_address;
    bpf_core_read(&body->error, sizeof(body->error), &info->si_errno);
    bpf_core_read(&body->code, sizeof(body->code), &info->si_code);
    bpf_core_read(&body->sender_pid, sizeof(body->sender_pid), &info->_sifields._kill._pid);
    bpf_core_read(&body->sender_uid, sizeof(body->sender_uid), &info->_sifields._kill._uid);
    bpf_core_read(&body->address, sizeof(body->address), &info->_sifields._sigfault._addr);
    return 0;
}

SEC("raw_tracepoint/signal_deliver")
int trace_signal_deliver(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);
    if (!is_lifecycle_task_tracked(pid, tid)) {
        return 0;
    }

    u32 config_key = 0;
    u32 *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config || !(*config & CONFIG_EMIT_SIGNAL)) {
        return 0;
    }

    u32 signo = (u32)ctx->args[0];
    if (signo == SIGNAL_NUMBER_CHLD) {
        return 0;
    }
    unsigned long info_address = ctx->args[1];
    struct signal_event_v2 body = {};
    if (populate_signal_event_v2(ctx, info_address, signo, *config, &body)) {
        return 0;
    }

    emit_signal_event_v2(pid, tid, &body);
    return 0;
}

SEC("raw_tracepoint/signal_generate")
int trace_signal_generate(struct bpf_raw_tracepoint_args *ctx)
{
    u32 signo = (u32)ctx->args[0];
    if (signo != SIGNAL_NUMBER_CHLD) {
        return 0;
    }
    struct task_struct *target = (void *)ctx->args[2];
    if (!target) {
        return 0;
    }
    u32 pid = BPF_CORE_READ(target, tgid);
    u32 tid = BPF_CORE_READ(target, pid);
    if (!is_lifecycle_task_tracked(pid, tid)) {
        return 0;
    }
    u32 config_key = 0;
    u32 *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config || !(*config & CONFIG_EMIT_SIGNAL)) {
        return 0;
    }
    struct signal_event_v2 body = {};
    u32 body_config = *config & ~CONFIG_CAPTURE_STACK;
    if (populate_signal_event_v2(ctx, ctx->args[1], signo, body_config, &body)) {
        return 0;
    }
    body.stack_id = target_pending_stack_id(tid);
    emit_signal_event_v2(pid, tid, &body);
    return 0;
}

#endif
