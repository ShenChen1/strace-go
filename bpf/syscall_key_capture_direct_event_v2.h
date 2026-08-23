#ifndef STRACE_GO_SYSCALL_KEY_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_KEY_CAPTURE_DIRECT_EVENT_V2_H

struct key_bytes_capture_request {
    u16 arg_index;
    u16 tlv_flags;
    u64 user_ptr;
    u64 raw_user_len;
};

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
    const struct key_bytes_capture_request *request,
    u16 *event_flags)
{
    u32 user_len = payload_tlv_clamp_u32(request->raw_user_len);
    if (!request->user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(
        request->raw_user_len, KEY_DIRECT_PAYLOAD_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, KEY_DIRECT_PAYLOAD_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(
            payload_data, copied_len, (void *)request->user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (event_flags && probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            request->arg_index,
            request->tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_keyctl_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags);

static __always_inline u32 capture_key_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (sys_id == SYS_KEYCTL) {
        return capture_keyctl_payload_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }

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
        struct key_bytes_capture_request request = {};
        request.arg_index = 2;
        request.user_ptr = ctx->args[2];
        request.raw_user_len = ctx->args[3];
        payload_size += capture_key_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request,
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

static __always_inline u32 capture_keyctl_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 operation = ctx->args[0];
    if (operation == KEYCTL_JOIN_SESSION_KEYRING) {
        return capture_key_string_tlv_direct(
            ptr,
            payload_offset,
            1,
            ctx->args[1],
            KEY_DIRECT_DESCRIPTION_MAX);
    }
    if (operation == KEYCTL_UPDATE || operation == KEYCTL_INSTANTIATE) {
        struct key_bytes_capture_request request = {};
        request.arg_index = 2;
        request.user_ptr = ctx->args[2];
        request.raw_user_len = ctx->args[3];
        return capture_key_bytes_tlv_direct(
            ptr,
            payload_offset,
            &request,
            event_flags);
    }
    if (operation == KEYCTL_SEARCH) {
        u32 payload_size = capture_key_string_tlv_direct(
            ptr,
            payload_offset,
            2,
            ctx->args[2],
            KEY_DIRECT_TYPE_MAX);
        payload_size += capture_key_string_tlv_direct(
            ptr,
            payload_offset + payload_size,
            3,
            ctx->args[3],
            KEY_DIRECT_DESCRIPTION_MAX);
        return payload_size;
    }
    return 0;
}

static __always_inline u32 capture_keyctl_output_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u64 operation = p->args[0];
    if (!is_keyctl_output_operation(operation) || ret_value <= 0) {
        return 0;
    }
    u16 arg_index = keyctl_output_arg_index(operation);
    u64 user_ptr = keyctl_output_user_ptr(p);
    u64 user_len = keyctl_output_user_len(p, ret_value);
    struct key_bytes_capture_request request = {
        .arg_index = arg_index,
        .tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        .user_ptr = user_ptr,
        .raw_user_len = user_len,
    };
    return capture_key_bytes_tlv_direct(
        ptr,
        payload_offset,
        &request,
        event_flags);
}

#endif
