#ifndef STRACE_GO_RUNTIME_STATS_H
#define STRACE_GO_RUNTIME_STATS_H

static __always_inline int should_trace_syscall(u32 sys_id, u32 *cfg)
{
    if (!cfg || !(*cfg & CONFIG_SYSCALL_FILTER)) {
        return 1;
    }

    u32 *enabled = bpf_map_lookup_elem(&syscall_filter_map, &sys_id);
    if (*cfg & CONFIG_SYSCALL_FILTER_NEGATED) {
        return enabled ? 0 : 1;
    }
    return enabled ? 1 : 0;
}

static __always_inline int is_fd_state_direct_syscall(u32 sys_id)
{
    switch (sys_id) {
    case SYS_OPEN:
    case SYS_OPENAT:
    case SYS_OPENAT2:
    case SYS_OPEN_TREE:
    case SYS_CREAT:
    case SYS_CLOSE:
    case SYS_CLOSE_RANGE:
    case SYS_DUP:
    case SYS_DUP2:
    case SYS_DUP3:
    case SYS_EPOLL_CREATE:
    case SYS_TIMERFD_CREATE:
    case SYS_EVENTFD:
    case SYS_EVENTFD2:
    case SYS_EPOLL_CREATE1:
    case SYS_FCNTL:
    case SYS_PIPE:
    case SYS_PIPE2:
    case SYS_SOCKETPAIR:
    case SYS_CHDIR:
    case SYS_FCHDIR:
    case SYS_FACCESSAT:
    case SYS_FACCESSAT2:
    case SYS_FCHMODAT:
    case SYS_MKDIRAT:
    case SYS_NEWFSTATAT:
    case SYS_FSTAT:
        return 1;
    default:
        return 0;
    }
}

// IMPACT: when a -P path filter is active, fd-state syscalls must keep flowing
// through the ringbuf even if excluded from the trace set, so the Go side can
// maintain a deterministic fd -> path map instead of racy live /proc reads.
static __always_inline int is_fd_state_tracked(u32 sys_id, u32 *cfg)
{
    return cfg && (*cfg & CONFIG_FD_STATE) && is_fd_state_direct_syscall(sys_id);
}

static __always_inline struct bpf_stats *lookup_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void record_ringbuf_reserve_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->ringbuf_reserve_fail++;
    }
}

static __always_inline void record_ringbuf_copy_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->ringbuf_copy_fail++;
    }
}

static __always_inline void record_payload_truncated_event(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->payload_truncated_events++;
    }
}

static __always_inline void record_pending_update_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->pending_update_fail++;
    }
}

static __always_inline void record_orphan_exit(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->orphan_exit++;
    }
}

static __always_inline void record_pending_mismatch(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->pending_mismatch++;
    }
}

#endif
