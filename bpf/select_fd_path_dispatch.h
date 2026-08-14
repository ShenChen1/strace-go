#ifndef STRACE_GO_SELECT_FD_PATH_DISPATCH_H
#define STRACE_GO_SELECT_FD_PATH_DISPATCH_H

/* Tail-call fragments capture one nested select FD path per verifier unit. */
#ifndef STRACE_GO_CORE_ONLY

#if defined(STRACE_GO_ENTER_CONTROL)

struct select_fd_path_fragment_context {
    struct pending_syscall *pending;
    struct fd_path_scratch *scratch;
};

static __always_inline int load_select_fd_path_fragment_context(
    struct trace_event_raw_sys_enter *ctx,
    struct select_fd_path_fragment_context *fragment)
{
    if ((u32)ctx->id != SYS_SELECT) {
        return 0;
    }
    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg || !(*cfg & CONFIG_FD_STATE)) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);
    struct pending_syscall *pending = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!pending || pending->pid != pid || pending->tid != tid ||
        pending->sys_id != SYS_SELECT) {
        return 0;
    }
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch || scratch->nested_fd_count == 0 ||
        scratch->nested_fd_count > SELECT_DIRECT_FD_PATH_MAX) {
        return 0;
    }
    fragment->pending = pending;
    fragment->scratch = scratch;
    return 1;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select_fd_path0(struct trace_event_raw_sys_enter *ctx) {
    struct select_fd_path_fragment_context fragment = {};
    if (!load_select_fd_path_fragment_context(ctx, &fragment)) {
        return 0;
    }
    emit_select_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd0);
    if (fragment.scratch->nested_fd_count > 1) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SELECT_FD_PATH1);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select_fd_path1(struct trace_event_raw_sys_enter *ctx) {
    struct select_fd_path_fragment_context fragment = {};
    if (!load_select_fd_path_fragment_context(ctx, &fragment) ||
        fragment.scratch->nested_fd_count <= 1) {
        return 0;
    }
    emit_select_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd1);
    if (fragment.scratch->nested_fd_count > 2) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SELECT_FD_PATH2);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select_fd_path2(struct trace_event_raw_sys_enter *ctx) {
    struct select_fd_path_fragment_context fragment = {};
    if (!load_select_fd_path_fragment_context(ctx, &fragment) ||
        fragment.scratch->nested_fd_count <= 2) {
        return 0;
    }
    emit_select_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd2);
    if (fragment.scratch->nested_fd_count > 3) {
        bpf_tail_call(ctx, &enter_progs, ENTER_PROG_SELECT_FD_PATH3);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_select_fd_path3(struct trace_event_raw_sys_enter *ctx) {
    struct select_fd_path_fragment_context fragment = {};
    if (!load_select_fd_path_fragment_context(ctx, &fragment) ||
        fragment.scratch->nested_fd_count <= 3) {
        return 0;
    }
    emit_select_fd_path_fragment_event_v2_direct(
        fragment.pending,
        fragment.scratch->nested_fd3);
    return 0;
}

#endif

#endif

#endif
