#ifndef STRACE_GO_ENTER_DISPATCH_H
#define STRACE_GO_ENTER_DISPATCH_H

/*
 * enter_dispatch.h - sys_enter family handlers used as bpf_tail_call targets.
 *
 * Only trace_sys_enter (the dispatcher) is attached to the raw_syscalls/sys_enter
 * tracepoint. Each handler below is loaded into enter_progs (PROG_ARRAY) and
 * invoked by the dispatcher according to the syscall id. The dispatcher already
 * performed filter/config checks, so handlers only capture payloads and save
 * pending metadata. Fragment handlers (iovec_base, sendmsg_base, ...) are
 * chained via bpf_tail_call from their family handler; the family handler
 * always saves pending metadata before chaining because tail calls never return.
 */

enum enter_prog_index {
    ENTER_PROG_TERMINATING = 1,
    ENTER_PROG_EXEC = 2,
    ENTER_PROG_PATH_STAT = 3,
    ENTER_PROG_PATH_ONLY = 4,
    ENTER_PROG_DUAL_PATH = 5,
    ENTER_PROG_OPENAT2 = 6,
    ENTER_PROG_READLINK = 7,
    ENTER_PROG_MISC_STRUCT = 8,
    ENTER_PROG_SMALL_STRUCT = 9,
    ENTER_PROG_ITIMER = 10,
    ENTER_PROG_TIME_STRUCT = 11,
    ENTER_PROG_SIGNAL = 12,
    ENTER_PROG_FILE_TIME = 13,
    ENTER_PROG_SLEEP = 14,
    ENTER_PROG_FUTEX = 15,
    ENTER_PROG_CACHESTAT = 16,
    ENTER_PROG_CAPABILITY = 17,
    ENTER_PROG_MEMFD = 18,
    ENTER_PROG_PRCTL = 19,
    ENTER_PROG_CLONE3 = 20,
    ENTER_PROG_BPF = 21,
    ENTER_PROG_IOVEC = 22,
    ENTER_PROG_MSG = 23,
    ENTER_PROG_MMSG = 24,
    ENTER_PROG_FCNTL = 25,
    ENTER_PROG_IOCTL = 26,
    ENTER_PROG_NETWORK = 27,
    ENTER_PROG_KEY = 28,
    ENTER_PROG_XATTR = 29,
    ENTER_PROG_FS = 30,
    ENTER_PROG_AIO = 31,
    ENTER_PROG_POLL = 32,
    ENTER_PROG_SELECT = 33,
    ENTER_PROG_EPOLL = 34,
    ENTER_PROG_NO_PAYLOAD_DIRECT = 35,
    ENTER_PROG_PAYLOAD_DIRECT = 36,
    /* chained fragment handlers, never dispatched by syscall id */
    ENTER_PROG_IOVEC_BASE = 37,
    ENTER_PROG_SENDMSG_BASE = 38,
    ENTER_PROG_SENDMMSG_BASE0 = 39,
    ENTER_PROG_SENDMMSG_BASE1 = 40,
    ENTER_PROG_AIO_IOVEC = 41,
    ENTER_PROG_AIO_BUF = 42,
    ENTER_PROG_QUOTA = 43,
};

#define ENTER_PROLOGUE(ctx)                                                \
    u32 sys_id = (u32)(ctx)->id;                                           \
    u32 tid = (u32)bpf_get_current_pid_tgid();                             \
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);                     \
    u64 enter_time = bpf_ktime_get_ns();                                   \
    u32 cfg_key = 0;                                                       \
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);                 \
    volatile s32 stack_id = -1;                                           \
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {                            \
        stack_id = bpf_get_stackid((void *)(ctx), &stack_traces, BPF_F_USER_STACK); \
    }

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_terminating(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (tid == pid) {
        u32 val = 1;
        bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY);
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    emit_terminating_exit_event_v2_direct(pid, tid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_exec(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    s32 probe_ret_enter = 0;
    u32 *exited = bpf_map_lookup_elem(&main_exited_map, &pid);
    if (exited && *exited == 1) {
        probe_ret_enter = 1;
    }
    emit_exec_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time, probe_ret_enter);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (tid != pid) {
        bpf_map_update_elem(&pending_exec_map, &pid, &tid, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_path_stat(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_path_stat_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_path_only(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_path_only_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_dual_path(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_dual_path_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_openat2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_readlink(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_readlink_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_misc_struct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_misc_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_small_struct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_small_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_itimer(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_itimer_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_time_struct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_time_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_signal(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_signal_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, -1);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (sys_id == SYS_RT_SIGSUSPEND && should_emit_signal_sigsuspend_marker(tid, pid)) {
        emit_signal_sigsuspend_marker_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_file_time(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_file_time_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_sleep(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id == SYS_NANOSLEEP) {
        emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], -1);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        if (should_emit_nanosleep_suspended_marker(tid, pid)) {
            emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], 3);
        }
        return 0;
    }
    if (sys_id == SYS_CLOCK_NANOSLEEP) {
        emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 2, ctx->args[2], -1);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_futex(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id == SYS_FUTEX) {
        emit_futex_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_WAIT) {
        emit_futex_wait_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_WAITV) {
        emit_futex_waitv_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_REQUEUE) {
        emit_futex_requeue_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_cachestat(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_cachestat_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_capability(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_capability_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_memfd(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_memfd_create_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_prctl(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_prctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_clone3_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_bpf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_iovec(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_iovec_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (is_iovec_base_enter_direct_syscall(sys_id)) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_IOVEC_BASE);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_iovec_base(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (!is_iovec_base_enter_direct_syscall(sys_id)) {
        return 0;
    }
    emit_iovec_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_msg(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_msg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_msg_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (sys_id == SYS_SENDMSG) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SENDMSG_BASE);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_sendmsg_base(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMSG) {
        return 0;
    }
    emit_sendmsg_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_mmsg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (sys_id == SYS_SENDMMSG) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SENDMMSG_BASE0);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_sendmmsg_base0(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_sendmmsg_base0_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SENDMMSG_BASE1);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_sendmmsg_base1(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_sendmmsg_base1_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_fcntl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_ioctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_network(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    struct network_direct_args network_args = {};
    network_args.args[0] = ctx->args[0];
    network_args.args[1] = ctx->args[1];
    network_args.args[2] = ctx->args[2];
    network_args.args[3] = ctx->args[3];
    network_args.args[4] = ctx->args[4];
    network_args.args[5] = ctx->args[5];
    u32 sockaddr_len = 0;
    emit_network_enter_event_v2_direct(pid, tid, sys_id, &network_args, enter_time, &sockaddr_len);
    save_pending_network_syscall_args(tid, pid, sys_id, &network_args, enter_time, stack_id, sockaddr_len);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_key(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_key_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_xattr(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_xattr_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_fs(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_fs_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_aio(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id == SYS_IO_SUBMIT) {
        emit_aio_submit_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_AIO_IOVEC);
        return 0;
    }
    emit_aio_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_aio_iovec(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_IO_SUBMIT) {
        return 0;
    }
    emit_aio_submit_iovec_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_AIO_BUF);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_aio_buf(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_IO_SUBMIT) {
        return 0;
    }
    emit_aio_submit_buf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_poll(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_poll_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_select_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_epoll(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (is_epoll_ctl_direct_syscall(sys_id)) {
        emit_epoll_ctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (is_epoll_pwait2_direct_syscall(sys_id)) {
        emit_epoll_pwait2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_no_payload_direct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_payload_direct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

#endif
