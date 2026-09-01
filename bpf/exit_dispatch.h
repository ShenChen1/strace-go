#ifndef STRACE_GO_EXIT_DISPATCH_H
#define STRACE_GO_EXIT_DISPATCH_H

/*
 * exit_dispatch.h - sys_exit family handlers used as bpf_tail_call targets.
 *
 * Only trace_sys_exit (the dispatcher) is attached to raw_syscalls/sys_exit.
 * It filters by the raw syscall id and tail calls the matching handler. The
 * handler resolves pending metadata (including the non-leader exec
 * pending_exec_map path) and is the sole normal-path consumer that deletes it.
 * recvmmsg OUT fragments are chained base01 -> base23 -> final so
 * ringbuf ordering matches the old attach order; sendmmsg is dispatched
 * straight to the final handler.
 */

static __always_inline void emit_exit_dispatch_fallback(
    u32 pid,
    u32 tid,
    u32 sys_id,
    s64 ret_value)
{
    u32 pending_tid = tid;
    u32 pending_exec_lookup = 0;
    struct pending_syscall *p = lookup_pending_syscall_for_exit(
        pid,
        tid,
        ret_value,
        &pending_tid,
        &pending_exec_lookup);
    if (!p) {
        record_unmatched_exit_if_needed(pid, tid, sys_id, ret_value);
        return;
    }
    if (!validate_pending_syscall_exit(p, sys_id, pid, pending_tid)) return;

    u64 duration = pending_syscall_duration(p);
    emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    consume_pending_syscall(pid, pending_tid, p, pending_exec_lookup);
}

#define EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid) \
    s64 ret_value = (ctx)->ret;                                                    \
    u32 exit_sys_id = (u32)(ctx)->id;                                               \
    u64 pid_tgid = bpf_get_current_pid_tgid();                                      \
    u32 tid = (u32)pid_tgid;                                                        \
    u32 pid = (u32)(pid_tgid >> 32);                                                \
    u32 is_pending_lookup = 0;                                                     \
    u32 pending_tid = tid;                                                         \
    struct pending_syscall *p = lookup_pending_syscall_for_exit(                   \
        pid, tid, ret_value, &pending_tid, &is_pending_lookup);                    \
    if (!p) {                                                                      \
        record_unmatched_exit_if_needed(pid, tid, exit_sys_id, ret_value);          \
        return 0;                                                                  \
    }                                                                              \
    if (!validate_pending_syscall_exit(                                             \
            p, exit_sys_id, pid, pending_tid)) return 0;                             \
    u64 duration = pending_syscall_duration(p);                                    \

static __always_inline int emit_generic_exit_fd_time_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (is_fd_state_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_fd_state_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_exit_payload_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_payload_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_time_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_time_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_gettimeofday_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_gettimeofday_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_clock_time_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_time_struct_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_itimer_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_itimer_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_timex_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_timex_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_sleep_direct_syscall(p->sys_id)) {
        emit_sleep_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    return 0;
}

static __always_inline int emit_generic_exit_struct_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (is_stat_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_stat_struct_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_waitid_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_waitid_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_signal_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_signal_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_getcwd_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_getcwd_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_readlink_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_readlink_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_fd_array_direct_syscall(p->sys_id) && ret_value == 0) {
        emit_fd_array_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_misc_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_misc_struct_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    return 0;
}

static __always_inline int emit_generic_exit_async_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (is_small_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_small_struct_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_cachestat_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_cachestat_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (p->sys_id == SYS_CAPGET && ret_value >= 0) {
        emit_capability_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_prctl_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_prctl_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_aio_getevents_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_aio_getevents_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_aio_setup_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_poll_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_poll_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    return 0;
}

static __always_inline int emit_generic_exit_io_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (is_bpf_direct_syscall(p->sys_id) &&
        emit_bpf_exit_event_v2_direct(p, ret_value, duration)) {
        return 1;
    }
    if (is_keyctl_direct_syscall(p->sys_id) &&
        emit_keyctl_exit_event_v2_direct(p, ret_value, duration)) {
        return 1;
    }
    if (is_select_direct_syscall(p->sys_id) && ret_value >= 0) {
        emit_select_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_epoll_wait_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_getdents_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_getdents_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_exec_payload_direct_syscall(p->sys_id) && ret_value != 0) {
        emit_exec_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_xattr_get_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_xattr_get_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_xattr_list_direct_syscall(p->sys_id) && ret_value > 0) {
        emit_xattr_list_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    return 0;
}

static __always_inline int emit_generic_exit_control_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (is_fcntl_direct_syscall(p->sys_id)) {
        emit_fcntl_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_ioctl_direct_syscall(p->sys_id)) {
        emit_ioctl_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    if (is_network_direct_syscall(p->sys_id)) {
        emit_network_exit_event_v2_direct(p, ret_value, duration);
        return 1;
    }
    return 0;
}

static __always_inline void emit_generic_exit_event(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
}

#ifndef STRACE_GO_CORE_ONLY

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_generic(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    emit_generic_exit_event(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_namespace(struct trace_event_raw_sys_exit *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id != SYS_CLONE && sys_id != SYS_CLONE3 &&
        sys_id != SYS_SETNS && sys_id != SYS_UNSHARE) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    emit_namespace_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_pid_namespace(struct trace_event_raw_sys_exit *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id != SYS_GETPID && sys_id != SYS_GETTID &&
        sys_id != SYS_FORK && sys_id != SYS_VFORK) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    emit_pid_namespace_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_path(struct trace_event_raw_sys_exit *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (!is_path_only_direct_syscall(sys_id) &&
        !is_dual_path_direct_syscall(sys_id) &&
        !is_open_creat_path_direct_syscall(sys_id) &&
        !is_openat2_direct_syscall(sys_id)) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_path_only_direct_syscall(p->sys_id) &&
        !is_dual_path_direct_syscall(p->sys_id) &&
        !is_open_creat_path_direct_syscall(p->sys_id) &&
        !is_openat2_direct_syscall(p->sys_id)) {
        return 0;
    }

    if (is_path_only_direct_syscall(p->sys_id)) {
        emit_path_only_exit_event_v2_direct(p, ret_value, duration);
    } else if (is_dual_path_direct_syscall(p->sys_id)) {
        emit_dual_path_exit_event_v2_direct(p, ret_value, duration);
    } else if (is_openat2_direct_syscall(p->sys_id)) {
        emit_openat2_exit_event_v2_direct(p, ret_value, duration);
    } else {
        emit_open_creat_fd_state_path_exit_event_v2_direct(p, ret_value, duration);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_iovec_base(struct trace_event_raw_sys_exit *ctx) {
    if (!is_iovec_base_exit_direct_syscall((u32)ctx->id)) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_iovec_base_exit_direct_syscall(p->sys_id)) {
        return 0;
    }

    if (ret_value > 0) {
        emit_iovec_base_exit_event_v2_direct(p, ret_value, duration);
    } else {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
    }
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_msg(struct trace_event_raw_sys_exit *ctx) {
    // recvmsg owns a separate kretprobe fragment chain; only sendmsg exits here.
    if ((u32)ctx->id != SYS_SENDMSG) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (p->sys_id != SYS_SENDMSG) {
        return 0;
    }

    emit_single_msg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_mmsg_final(struct trace_event_raw_sys_exit *ctx) {
    if (!is_mmsg_direct_syscall((u32)ctx->id)) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_mmsg_direct_syscall(p->sys_id)) {
        return 0;
    }

    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_recvmmsg_base01(struct trace_event_raw_sys_exit *ctx) {
    if ((u32)ctx->id != SYS_RECVMMSG) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (p->sys_id != SYS_RECVMMSG) {
        return 0;
    }

    emit_recvmmsg_base0_exit_fragment_event_v2_direct(p, ret_value, duration);
    emit_recvmmsg_base1_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &exit_progs, EXIT_PROG_RECVMMSG_BASE23);
    // A failed chain call must still close the syscall and consume pending state.
    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_recvmmsg_base23(struct trace_event_raw_sys_exit *ctx) {
    if ((u32)ctx->id != SYS_RECVMMSG) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (p->sys_id != SYS_RECVMMSG) {
        return 0;
    }

    emit_recvmmsg_base2_exit_fragment_event_v2_direct(p, ret_value, duration);
    emit_recvmmsg_base3_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &exit_progs, EXIT_PROG_MMSG_FINAL);
    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

#endif

#endif
