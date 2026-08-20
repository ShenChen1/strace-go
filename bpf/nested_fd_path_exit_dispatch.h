#ifndef STRACE_GO_NESTED_FD_PATH_EXIT_DISPATCH_H
#define STRACE_GO_NESTED_FD_PATH_EXIT_DISPATCH_H

/* Exit fragments emit probe-site paths before the completed epoll event. */
#ifndef STRACE_GO_CORE_ONLY

#if defined(STRACE_GO_HANDLER_EXIT)

struct nested_fd_path_exit_fragment_context {
    struct pending_syscall *pending;
    struct fd_path_scratch *scratch;
    u32 pid;
    u32 tid;
    u32 pending_tid;
    u32 pending_exec_lookup;
    u32 nested_fd_count;
    s64 ret_value;
    u64 duration;
};

static __always_inline int load_nested_fd_path_exit_context(
    struct trace_event_raw_sys_exit *ctx,
    struct nested_fd_path_exit_fragment_context *fragment)
{
    u32 sys_id = (u32)ctx->id;
    if (!is_epoll_wait_direct_syscall(sys_id)) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);
    u32 pending_tid = tid;
    u32 pending_exec_lookup = 0;
    struct pending_syscall *pending = lookup_pending_syscall_for_exit(
        pid,
        tid,
        ctx->ret,
        &pending_tid,
        &pending_exec_lookup);
    if (!pending) {
        record_unmatched_exit_if_needed(pid, tid, sys_id, ctx->ret);
        return 0;
    }
    if (!validate_pending_syscall_exit(pending, sys_id, pid, pending_tid)) {
        return 0;
    }

    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch || scratch->nested_fd_count == 0 ||
        scratch->nested_fd_count > FD_PATH_NESTED_MAX) {
        return 0;
    }
    fragment->pending = pending;
    fragment->scratch = scratch;
    fragment->pid = pid;
    fragment->tid = tid;
    fragment->pending_tid = pending_tid;
    fragment->pending_exec_lookup = pending_exec_lookup;
    fragment->nested_fd_count = scratch->nested_fd_count;
    fragment->ret_value = ctx->ret;
    fragment->duration = pending_syscall_duration(pending);
    return 1;
}

static __always_inline void finish_nested_fd_path_exit(
    struct nested_fd_path_exit_fragment_context *fragment)
{
    emit_epoll_wait_exit_event_v2_direct(
        fragment->pending,
        fragment->ret_value,
        fragment->duration);
    consume_pending_syscall(
        fragment->pid,
        fragment->pending_tid,
        fragment->pending,
        fragment->pending_exec_lookup);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_nested_fd_path0(struct trace_event_raw_sys_exit *ctx)
{
    struct nested_fd_path_exit_fragment_context fragment = {};
    if (!load_nested_fd_path_exit_context(ctx, &fragment)) {
        return 0;
    }
    emit_nested_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd0);
    if (fragment.nested_fd_count > 1) {
        bpf_tail_call(ctx, &exit_progs, EXIT_PROG_NESTED_FD_PATH1);
    }
    finish_nested_fd_path_exit(&fragment);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_nested_fd_path1(struct trace_event_raw_sys_exit *ctx)
{
    struct nested_fd_path_exit_fragment_context fragment = {};
    if (!load_nested_fd_path_exit_context(ctx, &fragment) ||
        fragment.nested_fd_count <= 1) {
        return 0;
    }
    emit_nested_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd1);
    if (fragment.nested_fd_count > 2) {
        bpf_tail_call(ctx, &exit_progs, EXIT_PROG_NESTED_FD_PATH2);
    }
    finish_nested_fd_path_exit(&fragment);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_nested_fd_path2(struct trace_event_raw_sys_exit *ctx)
{
    struct nested_fd_path_exit_fragment_context fragment = {};
    if (!load_nested_fd_path_exit_context(ctx, &fragment) ||
        fragment.nested_fd_count <= 2) {
        return 0;
    }
    emit_nested_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd2);
    if (fragment.nested_fd_count > 3) {
        bpf_tail_call(ctx, &exit_progs, EXIT_PROG_NESTED_FD_PATH3);
    }
    finish_nested_fd_path_exit(&fragment);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_nested_fd_path3(struct trace_event_raw_sys_exit *ctx)
{
    struct nested_fd_path_exit_fragment_context fragment = {};
    if (!load_nested_fd_path_exit_context(ctx, &fragment) ||
        fragment.nested_fd_count <= 3) {
        return 0;
    }
    emit_nested_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd3);
    finish_nested_fd_path_exit(&fragment);
    return 0;
}

#endif

#endif

#endif
