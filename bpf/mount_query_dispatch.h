#ifndef STRACE_GO_MOUNT_QUERY_DISPATCH_H
#define STRACE_GO_MOUNT_QUERY_DISPATCH_H

#ifndef STRACE_GO_CORE_ONLY

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_mount_query(struct trace_event_raw_sys_exit *ctx)
{
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_mount_query_direct_syscall(p->sys_id)) {
        return 0;
    }

    if (ret_value >= 0) {
        emit_mount_query_exit_event_v2_direct(p, ret_value, duration);
    } else {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

#endif

#endif
