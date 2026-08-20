#ifndef STRACE_GO_EXIT_DIRECT_DISPATCH_H
#define STRACE_GO_EXIT_DIRECT_DISPATCH_H

#ifndef STRACE_GO_CORE_ONLY

/*
 * Direct exit families keep large payload emitters out of exit_generic.
 * Each handler owns one pending lookup/consume pair and falls back to the
 * ordinary exit event when its family emitter declines the return value.
 */

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_fd_time(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!emit_generic_exit_fd_time_event(p, ret_value, duration)) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_struct(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!emit_generic_exit_struct_event(p, ret_value, duration)) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_async(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!emit_generic_exit_async_event(p, ret_value, duration)) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_io(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (is_epoll_wait_direct_syscall(p->sys_id) && ret_value > 0) {
        u32 nested_fd_count = collect_epoll_fd_path_candidates_direct(p, ret_value);
        if (nested_fd_count > 0) {
            struct trace_event_raw_sys_exit *volatile tail_ctx = ctx;
            bpf_tail_call_static((void *)tail_ctx, &exit_progs, EXIT_PROG_NESTED_FD_PATH0);
        }
        emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);
    } else if (!emit_generic_exit_io_event(p, ret_value, duration)) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_control(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!emit_generic_exit_control_event(p, ret_value, duration)) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

#endif

#endif
