#ifndef STRACE_GO_NAMESPACE_DISPATCH_H
#define STRACE_GO_NAMESPACE_DISPATCH_H

static __always_inline int namespace_clone_flags(
    struct pending_syscall *pending,
    u64 *flags)
{
    if (pending->sys_id == SYS_CLONE) {
        *flags = pending->args[0];
        return 1;
    }
    if (pending->sys_id != SYS_CLONE3 || pending->args[1] < sizeof(*flags) ||
        pending->args[0] == 0) {
        return 0;
    }
    return bpf_probe_read_user(
        flags,
        sizeof(*flags),
        (const void *)pending->args[0]) == 0;
}

SEC("raw_tracepoint/sched_process_fork")
int trace_namespace_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct pending_task_state *state = current_pending_task_state();
    if (!state || !state->valid) return 0;

    struct task_struct *child = (struct task_struct *)ctx->args[1];
    capture_pid_namespace_fork_child(state, child);

    u64 flags = 0;
    if (!namespace_clone_flags(&state->syscall, &flags) ||
        !(flags & NAMESPACE_FLAG_MASK)) {
        return 0;
    }
    if (read_namespace_snapshot(child, flags, &state->namespace_snapshot) < 0) {
        state->namespace_snapshot = (struct namespace_snapshot){};
    }
    return 0;
}

#endif
