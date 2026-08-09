#ifndef STRACE_GO_MOUNT_PATH_DISPATCH_H
#define STRACE_GO_MOUNT_PATH_DISPATCH_H

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mount_path(struct trace_event_raw_sys_enter *ctx)
{
    ENTER_PROLOGUE(ctx);
    if (!is_mount_path_direct_syscall(sys_id)) {
        return 0;
    }
    emit_mount_path_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

#endif
