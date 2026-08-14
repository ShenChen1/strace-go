#ifndef STRACE_GO_SYSCALL_KEY_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_KEY_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_key_string_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u32 max_len)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (max_len == KEY_DIRECT_TYPE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, KEY_DIRECT_TYPE_MAX);
    } else if (max_len == KEY_DIRECT_DESCRIPTION_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, KEY_DIRECT_DESCRIPTION_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, KEY_DIRECT_PAYLOAD_MAX);
    }

    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, max_len, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > max_len) {
            copied_len = max_len;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            arg_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_key_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 raw_user_len,
    u16 *event_flags)
{
    u32 user_len = payload_tlv_clamp_u32(raw_user_len);
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(raw_user_len, KEY_DIRECT_PAYLOAD_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, KEY_DIRECT_PAYLOAD_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
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
            PAYLOAD_TLV_KIND_BYTES,
            2,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_key_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u32 payload_size = capture_key_string_tlv_direct(
        ptr,
        payload_offset,
        0,
        ctx->args[0],
        KEY_DIRECT_TYPE_MAX);
    payload_size += capture_key_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        ctx->args[1],
        KEY_DIRECT_DESCRIPTION_MAX);

    if (sys_id == SYS_ADD_KEY) {
        payload_size += capture_key_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            ctx->args[2],
            ctx->args[3],
            event_flags);
    } else {
        payload_size += capture_key_string_tlv_direct(
            ptr,
            payload_offset + payload_size,
            2,
            ctx->args[2],
            KEY_DIRECT_PAYLOAD_MAX);
    }
    return payload_size;
}

#endif
