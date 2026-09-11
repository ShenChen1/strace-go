#ifndef STRACE_GO_ENTER_DISPATCH_H
#define STRACE_GO_ENTER_DISPATCH_H

#include "enter_runtime.h"

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

#ifndef STRACE_GO_CORE_ONLY

#if defined(STRACE_GO_ENTER_GENERIC)
SEC("tracepoint/raw_syscalls/sys_enter")
int enter_terminating(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (tid == pid) {
        u32 val = 1;
        if (bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY) != 0) {
            record_lifecycle_map_update_fail();
        }
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    emit_terminating_exit_event_v2_direct(pid, tid, sys_id, ctx, enter_time, stack_id);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_PAYLOAD)
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
        if (bpf_map_update_elem(&pending_exec_map, &pid, &tid, BPF_ANY) != 0) {
            record_lifecycle_map_update_fail();
        }
    }
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_PATH)
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
    emit_openat2_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
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
#endif

#if defined(STRACE_GO_ENTER_STRUCTURED)
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
    emit_cachestat_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
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
    int is_prog_load = is_bpf_prog_load_enter_direct(ctx);
    int is_uprobe_multi = is_bpf_uprobe_multi_enter_direct(ctx);
    int is_tracing_multi = is_bpf_tracing_multi_enter_direct(ctx);
    if (is_prog_load) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_PROG_LOAD);
    }
    if (is_uprobe_multi) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_UPROBE_MULTI);
    }
    if (is_tracing_multi) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_TRACING_MULTI);
    }
    emit_bpf_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (ctx->args[0] == BPF_DIRECT_MAP_GET_NEXT_KEY) {
        u32 key_size = bpf_map_get_next_key_key_size_direct(ctx->args[1], ctx->args[2]);
        if (key_size > 0) {
            save_pending_syscall_aux(tid, key_size);
        }
    } else if (ctx->args[0] == BPF_DIRECT_TASK_FD_QUERY) {
        u32 buf_len = 0;
        if (bpf_attr_read_u32_direct(
                ctx->args[1],
                ctx->args[2],
                BPF_DIRECT_TASK_FD_QUERY_BUF_LEN_OFF,
                &buf_len)) {
            save_pending_syscall_aux(tid, buf_len);
        }
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_bpf_uprobe_multi(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_bpf_uprobe_multi_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_bpf_tracing_multi(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_bpf_tracing_multi_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_bpf_prog_load(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_bpf_prog_load_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_BPF_PROG_LOAD_DEBUG);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_bpf_prog_load_debug(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_bpf_prog_load_debug_enter_fragment_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_MEMORY)
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
int enter_mmsg(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_mmsg_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_MMSG_BASE01);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_CONTROL)
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
    emit_fs_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_MEMORY)
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
#endif

#if defined(STRACE_GO_ENTER_CONTROL)
SEC("tracepoint/raw_syscalls/sys_enter")
int enter_poll(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    u32 fd_path_count = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        fd_path_count = collect_poll_fd_path_candidates_direct(
            sys_id,
            ctx->args[0],
            ctx->args[1]);
    }
    emit_poll_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (fd_path_count > 0) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_NESTED_FD_PATH0);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    u32 fd_path_count = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        fd_path_count = collect_select_fd_path_candidates_direct(
            ctx->args[0],
            ctx->args[1],
            ctx->args[2],
            ctx->args[3]);
    }
    emit_select_enter_event_v2_direct(ctx, pid, tid, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    if (fd_path_count > 0) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_NESTED_FD_PATH0);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_epoll(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (is_epoll_ctl_direct_syscall(sys_id)) {
        emit_epoll_ctl_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (is_epoll_pwait2_direct_syscall(sys_id)) {
        emit_epoll_pwait2_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_PATH)
SEC("tracepoint/raw_syscalls/sys_enter")
int enter_no_payload_direct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_fd_path_or_no_payload_enter_event_v2_direct(pid, tid, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_GENERIC)
SEC("tracepoint/raw_syscalls/sys_enter")
int enter_no_payload_generic(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_plain_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}
#endif

#if defined(STRACE_GO_ENTER_PAYLOAD)
SEC("tracepoint/raw_syscalls/sys_enter")
int enter_payload_direct(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    emit_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}
#endif

#endif

#endif
