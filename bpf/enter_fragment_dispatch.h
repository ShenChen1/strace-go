#ifndef STRACE_GO_ENTER_FRAGMENT_DISPATCH_H
#define STRACE_GO_ENTER_FRAGMENT_DISPATCH_H

/*
 * enter_fragment_dispatch.h - chained sys_enter payload fragments.
 *
 * These programs are reached only through tail calls from family handlers.
 * They may emit additional bounded payload fragments, but never save or
 * consume pending syscall state.
 */

#ifndef STRACE_GO_CORE_ONLY

#if defined(STRACE_GO_ENTER_MEMORY)

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
int enter_sendmsg_base(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMSG) {
        return 0;
    }
    emit_sendmsg_base_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
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

#endif

#endif

#endif
