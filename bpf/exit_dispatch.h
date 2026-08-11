#ifndef STRACE_GO_EXIT_DISPATCH_H
#define STRACE_GO_EXIT_DISPATCH_H

/*
 * exit_dispatch.h - sys_exit family handlers used as bpf_tail_call targets.
 *
 * Only trace_sys_exit (the dispatcher) is attached to raw_syscalls/sys_exit.
 * It resolves the pending syscall id and tail calls the matching handler, which
 * re-resolves pending metadata (including the non-leader exec pending_exec_map
 * path) and is the sole consumer that deletes it. recvmmsg OUT fragments are
 * chained base0 -> base1 -> final so ringbuf ordering matches the old attach
 * order; sendmmsg is dispatched straight to the final handler.
 */

enum exit_prog_index {
    EXIT_PROG_GENERIC = 0,
    EXIT_PROG_IOVEC_BASE = 1,
    EXIT_PROG_MSG = 2,
    EXIT_PROG_MMSG_FINAL = 3,
    EXIT_PROG_RECVMMSG_BASE0 = 4,
    EXIT_PROG_RECVMMSG_BASE1 = 5,
    EXIT_PROG_QUOTA = 6,
    EXIT_PROG_MOUNT_QUERY = 7,
};

#define EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid) \
    s64 ret_value = (ctx)->ret;                                                    \
    u32 tid = (u32)bpf_get_current_pid_tgid();                                     \
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);                             \
    u32 is_pending_lookup = 0;                                                     \
    u32 pending_tid = tid;                                                         \
    struct pending_syscall *p = lookup_pending_syscall_for_exit(                   \
        pid, tid, ret_value, &pending_tid, &is_pending_lookup);                    \
    if (!p) return 0;                                                              \
    if (!validate_pending_syscall_exit(                                             \
            p, (u32)(ctx)->id, pid, pending_tid)) return 0;

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_generic(struct trace_event_raw_sys_exit *ctx) {
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    if (is_sys_exit_direct_syscall(p->sys_id)) {
        if (is_exit_payload_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_payload_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_gettimeofday_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_gettimeofday_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_clock_time_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_time_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_itimer_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_itimer_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_timex_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_timex_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_sleep_direct_syscall(p->sys_id)) {
            emit_sleep_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_stat_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_stat_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_waitid_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_waitid_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_signal_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_signal_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_getcwd_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_getcwd_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_readlink_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_readlink_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_fd_array_direct_syscall(p->sys_id) && ret_value == 0) {
            emit_fd_array_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_path_only_direct_syscall(p->sys_id)) {
            emit_path_only_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_misc_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_misc_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_small_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_small_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_cachestat_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_cachestat_exit_event_v2_direct(p, ret_value, duration);
        } else if (p->sys_id == SYS_CAPGET && ret_value >= 0) {
            emit_capability_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_prctl_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_prctl_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_aio_getevents_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_aio_getevents_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_aio_setup_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_poll_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_poll_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_select_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_select_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_epoll_wait_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_getdents_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_getdents_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_exec_payload_direct_syscall(p->sys_id) && ret_value != 0) {
            emit_exec_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_xattr_get_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_xattr_get_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_xattr_list_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_xattr_list_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_fcntl_direct_syscall(p->sys_id)) {
            emit_fcntl_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_ioctl_direct_syscall(p->sys_id)) {
            emit_ioctl_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_network_direct_syscall(p->sys_id)) {
            emit_network_exit_event_v2_direct(p, ret_value, duration);
        } else {
            emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
        }
    } else {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
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

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
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
    if (!is_single_msg_direct_syscall((u32)ctx->id)) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (!is_single_msg_direct_syscall(p->sys_id)) {
        return 0;
    }

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
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

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_recvmmsg_base0(struct trace_event_raw_sys_exit *ctx) {
    if ((u32)ctx->id != SYS_RECVMMSG) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (p->sys_id != SYS_RECVMMSG) {
        return 0;
    }

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmmsg_base0_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &exit_progs, EXIT_PROG_RECVMMSG_BASE1);
    // A failed chain call must still close the syscall and consume pending state.
    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int exit_recvmmsg_base1(struct trace_event_raw_sys_exit *ctx) {
    if ((u32)ctx->id != SYS_RECVMMSG) {
        return 0;
    }
    EXIT_PROLOGUE(ctx, ret_value, tid, pid, p, is_pending_lookup, pending_tid);
    if (p->sys_id != SYS_RECVMMSG) {
        return 0;
    }

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmmsg_base1_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &exit_progs, EXIT_PROG_MMSG_FINAL);
    // A failed final call must not leave the syscall pending forever.
    emit_mmsg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, pending_tid, p, is_pending_lookup);
    return 0;
}

#endif
