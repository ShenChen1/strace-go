#ifndef STRACE_GO_QUOTA_DISPATCH_H
#define STRACE_GO_QUOTA_DISPATCH_H

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_quota(struct trace_event_raw_sys_enter *ctx)
{
    ENTER_PROLOGUE(ctx);
    if (!is_quota_direct_syscall(sys_id)) {
        return 0;
    }
    emit_quota_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_quota(struct trace_event_raw_sys_exit *ctx)
{
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_quota_direct_syscall(p->sys_id)) {
        return 0;
    }

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    u32 command = quota_direct_pending_command(p);
    if (ret_value >= 0 && quota_direct_has_exit_payload(command)) {
        emit_quota_exit_event_v2_direct(p, ret_value, duration);
    } else {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

#endif
