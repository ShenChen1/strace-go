#ifndef STRACE_GO_SYSCALL_MMSG_BYTES_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MMSG_BYTES_CAPTURE_DIRECT_EVENT_V2_H

static __noinline u32 capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 slot,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    u64 count = ctx->args[2];
    if (count <= slot) {
        return 0;
    }
    u16 iovec_arg_index = mmsg_iovec_arg_index_for_slot(slot);
    msg_ptr += (u64)slot * MMSGHDR_USER_SIZE;
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }
    return capture_iovec_base_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        iovec_arg_index,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_mmsg_bytes_base0_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(ptr, payload_offset, ctx, 0, event_flags);
}

static __always_inline u32 capture_mmsg_bytes_base1_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 1, event_flags);
}

static __always_inline u32 capture_mmsg_bytes_base2_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 2, event_flags);
}

static __always_inline u32 capture_mmsg_bytes_base3_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_bytes_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 3, event_flags);
}

static __always_inline u32 capture_recvmmsg_base_slot_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 slot,
    u16 *event_flags)
{
    if (p->args[2] <= slot) {
        return 0;
    }
    u16 iovec_arg_index = mmsg_iovec_arg_index_for_slot(slot);
    u64 msg_ptr = p->args[1] + (u64)slot * MMSGHDR_USER_SIZE;
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }
    return capture_iovec_base_exit_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        iovec_arg_index,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_recvmmsg_base0_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    return capture_recvmmsg_base_slot_exit_payloads_tlv_direct(ptr, payload_offset, p, 0, event_flags);
}

static __always_inline u32 capture_recvmmsg_base1_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    return capture_recvmmsg_base_slot_exit_payloads_tlv_direct(
        ptr, payload_offset, p, 1, event_flags);
}

static __always_inline u32 capture_recvmmsg_base2_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    return capture_recvmmsg_base_slot_exit_payloads_tlv_direct(
        ptr, payload_offset, p, 2, event_flags);
}

static __always_inline u32 capture_recvmmsg_base3_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    return capture_recvmmsg_base_slot_exit_payloads_tlv_direct(
        ptr, payload_offset, p, 3, event_flags);
}

#endif
