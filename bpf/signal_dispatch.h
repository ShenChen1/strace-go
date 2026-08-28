#ifndef STRACE_GO_SIGNAL_DISPATCH_H
#define STRACE_GO_SIGNAL_DISPATCH_H

#define SIGNAL_CODE_USER 0
#define SIGNAL_CODE_QUEUE -1
#define SIGNAL_CODE_TKILL -6

SEC("raw_tracepoint/signal_deliver")
int trace_signal_deliver(struct bpf_raw_tracepoint_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);
    if (!is_lifecycle_task_tracked(pid, tid)) {
        return 0;
    }

    u32 config_key = 0;
    u32 *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config || !(*config & CONFIG_EMIT_SIGNAL)) {
        return 0;
    }

    struct signal_event_v2 body = {};
    body.signo = (u32)ctx->args[0];
    unsigned long info_address = ctx->args[1];
    if (info_address > 1) {
        struct kernel_siginfo *info = (void *)info_address;
        bpf_core_read(&body.error, sizeof(body.error), &info->si_errno);
        bpf_core_read(&body.code, sizeof(body.code), &info->si_code);
        if (body.code == SIGNAL_CODE_USER || body.code == SIGNAL_CODE_QUEUE ||
            body.code == SIGNAL_CODE_TKILL) {
            bpf_core_read(&body.sender_pid, sizeof(body.sender_pid), &info->_sifields._kill._pid);
            bpf_core_read(&body.sender_uid, sizeof(body.sender_uid), &info->_sifields._kill._uid);
        }
    }

    emit_signal_event_v2(pid, tid, &body);
    return 0;
}

#endif
