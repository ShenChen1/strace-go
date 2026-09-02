#ifndef STRACE_GO_KVM_DISPATCH_H
#define STRACE_GO_KVM_DISPATCH_H

struct kvm_userspace_exit_tracepoint {
    u64 common;
    u32 reason;
    s32 error;
};

SEC("tracepoint/kvm/kvm_userspace_exit")
int trace_kvm_userspace_exit(struct kvm_userspace_exit_tracepoint *ctx)
{
    u32 config_key = 0;
    u32 *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config || !(*config & CONFIG_KVM_EXIT)) return 0;

    struct pending_task_state *state = current_pending_task_state();
    if (!state || !state->valid || state->syscall.sys_id != SYS_IOCTL ||
        state->syscall.args[1] != KVM_RUN_IOCTL) {
        return 0;
    }
    if (ctx->error < 0) {
        state->aux0 = 0;
        return 0;
    }

    state->aux0 = KVM_EXIT_AUX_VALID |
        (ctx->reason & KVM_EXIT_AUX_REASON_MASK);
    return 0;
}

#endif
