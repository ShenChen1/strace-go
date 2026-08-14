#ifndef STRACE_GO_SYSCALL_MMSG_STRUCT_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MMSG_STRUCT_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_mmsghdr_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 msg_ptr,
    u64 count,
    u16 *event_flags)
{
    if (!msg_ptr || count == 0) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MMSGHDR_DIRECT_BYTES_MAX;
    if (count == 1) {
        copied_len = MMSGHDR_USER_SIZE;
    } else if (count == 2) {
        copied_len = 2 * MMSGHDR_USER_SIZE;
    } else if (count == 3) {
        copied_len = 3 * MMSGHDR_USER_SIZE;
    }
    u32 user_len = copied_len;
    if (count > MMSGHDR_DIRECT_SLOT_MAX) {
        user_len = (u32)(MMSGHDR_DIRECT_SLOT_MAX + 1) * MMSGHDR_USER_SIZE;
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MMSGHDR_DIRECT_BYTES_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)msg_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            msg_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mmsg_timespec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 timeout_ptr,
    u16 *event_flags)
{
    if (!timeout_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MSG_DIRECT_TIMESPEC_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSG_DIRECT_TIMESPEC_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(
            payload_data,
            MSG_DIRECT_TIMESPEC_SIZE,
            (void *)timeout_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            4,
            tlv_flags,
            MSG_DIRECT_TIMESPEC_SIZE,
            copied_len,
            probe_ret,
            timeout_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __noinline u32 capture_mmsg_iovec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 msg_ptr,
    u16 iovec_arg_index,
    u16 *event_flags)
{
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }
    return capture_iovec_tlv_direct(
        ptr,
        payload_offset,
        iovec_arg_index,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_mmsg_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    u64 count = ctx->args[2];
    u32 sys_id = ctx->id;
    u64 timeout_ptr = ctx->args[4];
    if (count == 0) {
        return 0;
    }

    u32 payload_size = capture_mmsghdr_tlv_direct(
        ptr,
        payload_offset,
        0,
        msg_ptr,
        count,
        event_flags);
    if (sys_id == SYS_RECVMMSG) {
        payload_size += capture_mmsg_timespec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            0,
            timeout_ptr,
            event_flags);
    }
    return payload_size;
}

static __noinline u32 capture_mmsg_base_slot_enter_payloads_tlv_direct(
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
    msg_ptr += (u64)slot * MMSGHDR_USER_SIZE;
    return capture_mmsg_iovec_tlv_direct(
        ptr,
        payload_offset,
        msg_ptr,
        mmsg_iovec_arg_index_for_slot(slot),
        event_flags);
}

static __always_inline u32 capture_mmsg_base0_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_base_slot_enter_payloads_tlv_direct(ptr, payload_offset, ctx, 0, event_flags);
}

static __always_inline u32 capture_mmsg_base1_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 1, event_flags);
}

static __always_inline u32 capture_mmsg_base2_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 2, event_flags);
}

static __always_inline u32 capture_mmsg_base3_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    return capture_mmsg_base_slot_enter_payloads_tlv_direct(
        ptr, payload_offset, ctx, 3, event_flags);
}

static __always_inline u32 capture_mmsg_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    if (p->args[2] == 0) {
        return 0;
    }
    u32 payload_size = capture_mmsghdr_tlv_direct(
        ptr,
        payload_offset,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        p->args[1],
        p->args[2],
        event_flags);
    if (p->sys_id == SYS_RECVMMSG && ret_value > 0) {
        payload_size += capture_mmsg_timespec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            p->args[4],
            event_flags);
    }
    return payload_size;
}

#endif
