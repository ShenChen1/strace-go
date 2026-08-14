#ifndef STRACE_GO_EXIT_DIRECT_DISPATCH_H
#define STRACE_GO_EXIT_DIRECT_DISPATCH_H

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
    if (!emit_generic_exit_io_event(p, ret_value, duration)) {
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
