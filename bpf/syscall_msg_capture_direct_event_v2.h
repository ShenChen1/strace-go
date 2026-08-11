#ifndef STRACE_GO_SYSCALL_MSG_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MSG_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_msghdr_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 msg_ptr,
    u16 *event_flags)
{
    if (!msg_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MSGHDR_USER_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSGHDR_USER_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, MSGHDR_USER_SIZE, (void *)msg_ptr);
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
            MSGHDR_USER_SIZE,
            copied_len,
            probe_ret,
            msg_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_msg_name_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 msg_ptr,
    u32 copy_limit,
    u16 *event_flags)
{
    struct msg_direct_name name = {};
    if (msg_direct_read_name(msg_ptr, &name) < 0 || !name.ptr || name.len == 0) {
        return 0;
    }

    u32 user_len = name.len;
    u32 copied_len = name.len;
    if (copy_limit > 0 && copy_limit < copied_len) {
        copied_len = copy_limit;
    }
    if (copied_len > MSG_DIRECT_SOCKADDR_MAX) {
        copied_len = MSG_DIRECT_SOCKADDR_MAX;
    }
    s32 probe_ret = 0;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSG_DIRECT_SOCKADDR_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)name.ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_SOCKADDR,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            name.ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_single_msg_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    u32 payload_size = capture_msghdr_tlv_direct(
        ptr,
        payload_offset,
        0,
        msg_ptr,
        event_flags);
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return payload_size;
    }

    payload_size += capture_iovec_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        iov.ptr,
        iov.count,
        event_flags);
    payload_size += capture_msg_control_tlv_direct(
        ptr,
        payload_offset + payload_size,
        0,
        msg_ptr,
        event_flags);

    return payload_size;
}

static __always_inline u32 capture_sendmsg_base_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }

    return capture_iovec_base_payloads_tlv_direct(
        ptr,
        payload_offset,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_single_msg_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    u64 msg_ptr = p->args[1];
    u32 payload_size = capture_msghdr_tlv_direct(
        ptr,
        payload_offset,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        msg_ptr,
        event_flags);

    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_payloads_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iov.ptr,
        iov.count,
        event_flags);
    return payload_size;
}

#endif
