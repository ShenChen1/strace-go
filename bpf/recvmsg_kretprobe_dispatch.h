#ifndef STRACE_GO_RECVMSG_KRETPROBE_DISPATCH_H
#define STRACE_GO_RECVMSG_KRETPROBE_DISPATCH_H

/*
 * recvmsg_kretprobe_dispatch.h - serialized recvmsg OUT fragments.
 *
 * Only the dispatcher is attached to the kretprobe. The name and control
 * handlers are reached through recvmsg_progs and the final handler owns the
 * pending consume after all bounded fragments have been emitted.
 */

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_dispatch(struct pt_regs *ctx) {
    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_NAME);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_name(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = pending_syscall_duration(p);

    emit_recvmsg_name_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_CONTROL);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_control(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = pending_syscall_duration(p);

    emit_recvmsg_control_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_FINAL);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_final(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p || p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = pending_syscall_duration(p);

    emit_single_msg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, tid, p, 0);
    return 0;
}

#endif
