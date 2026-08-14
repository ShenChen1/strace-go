#ifndef STRACE_GO_ENTER_RUNTIME_H
#define STRACE_GO_ENTER_RUNTIME_H

/* Shared enter ProgArray indices and runtime contract for every enter handler. */
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
    /* Chained fragment handlers are never selected by syscall id. */
    ENTER_PROG_IOVEC_BASE = 37,
    ENTER_PROG_SENDMSG_BASE = 38,
    ENTER_PROG_MMSG_BASE01 = 39,
    ENTER_PROG_MMSG_BASE2 = 40,
    ENTER_PROG_MMSG_BASE3 = 41,
    ENTER_PROG_AIO_IOVEC = 42,
    ENTER_PROG_AIO_BUF = 43,
    ENTER_PROG_QUOTA = 44,
    ENTER_PROG_MOUNT_PATH = 45,
    ENTER_PROG_NO_PAYLOAD_GENERIC = 46,
};

#define ENTER_PROLOGUE(ctx)                                                \
    u32 sys_id = (u32)(ctx)->id;                                           \
    u64 pid_tgid = bpf_get_current_pid_tgid();                              \
    u32 tid = (u32)pid_tgid;                                                \
    u32 pid = (u32)(pid_tgid >> 32);                                        \
    u64 enter_time = bpf_ktime_get_ns();                                   \
    u32 cfg_key = 0;                                                       \
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);                 \
    volatile s32 stack_id = -1;                                           \
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {                            \
        stack_id = bpf_get_stackid((void *)(ctx), &stack_traces, BPF_F_USER_STACK); \
    }

// Tail-call failure owns the bounded event and pending state outside the dispatcher.
static __always_inline void emit_enter_dispatch_fallback(
    struct trace_event_raw_sys_enter *ctx,
    u32 pid,
    u32 tid,
    u32 *cfg,
    u64 enter_time)
{
    u32 sys_id = (u32)ctx->id;
    volatile s32 stack_id = -1;
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
}

#endif
