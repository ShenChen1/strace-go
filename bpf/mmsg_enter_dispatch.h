#ifndef STRACE_GO_MMSG_ENTER_DISPATCH_H
#define STRACE_GO_MMSG_ENTER_DISPATCH_H

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_base01(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (!is_mmsg_direct_syscall(sys_id)) {
        return 0;
    }
    emit_mmsg_base0_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    emit_mmsg_base1_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_MMSG_BASE2);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_base2(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (!is_mmsg_direct_syscall(sys_id)) {
        return 0;
    }
    emit_mmsg_base2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &enter_progs, ENTER_PROG_MMSG_BASE3);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_base3(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (!is_mmsg_direct_syscall(sys_id)) {
        return 0;
    }
    emit_mmsg_base3_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    if (sys_id == SYS_SENDMMSG) {
        bpf_tail_call(ctx, &mmsg_bytes_progs, MMSG_BYTES_PROG_BASE0);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_bytes0(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_mmsg_bytes_base0_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &mmsg_bytes_progs, MMSG_BYTES_PROG_BASE1);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_bytes1(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_mmsg_bytes_base1_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &mmsg_bytes_progs, MMSG_BYTES_PROG_BASE2);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_bytes2(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_mmsg_bytes_base2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    bpf_tail_call(ctx, &mmsg_bytes_progs, MMSG_BYTES_PROG_BASE3);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_mmsg_bytes3(struct trace_event_raw_sys_enter *ctx) {
    ENTER_PROLOGUE(ctx);
    if (sys_id != SYS_SENDMMSG) {
        return 0;
    }
    emit_mmsg_bytes_base3_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
    return 0;
}

#endif
