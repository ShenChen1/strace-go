#ifndef STRACE_GO_SYSCALL_FS_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FS_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_fs_string_tlv_direct(
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
    if (max_len == FS_DIRECT_FSCONFIG_VALUE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_VALUE_MAX);
    } else if (max_len == FS_DIRECT_FSCONFIG_KEY_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_KEY_MAX);
    } else if (max_len == FS_DIRECT_MOUNT_TYPE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_MOUNT_TYPE_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_MOUNT_STRING_MAX);
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

static __always_inline u32 capture_fs_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_user_len,
    u16 *event_flags)
{
    u64 masked_len = raw_user_len & FS_DIRECT_FSCONFIG_VALUE_LEN_MASK;
    u32 user_len = payload_tlv_clamp_u32(masked_len);
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(masked_len, FS_DIRECT_FSCONFIG_VALUE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_VALUE_MAX);
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
            arg_index,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mount_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    u32 payload_size = capture_fs_string_tlv_direct(
        ptr,
        payload_offset,
        0,
        ctx->args[0],
        FS_DIRECT_MOUNT_STRING_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        ctx->args[1],
        FS_DIRECT_MOUNT_STRING_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        2,
        ctx->args[2],
        FS_DIRECT_MOUNT_TYPE_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        4,
        ctx->args[4],
        FS_DIRECT_MOUNT_STRING_MAX);
    return payload_size;
}

static __always_inline u32 capture_fsconfig_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u32 payload_size = capture_fs_string_tlv_direct(
        ptr,
        payload_offset,
        2,
        ctx->args[2],
        FS_DIRECT_FSCONFIG_KEY_MAX);
    if (((u32)ctx->args[1]) == FS_DIRECT_FSCONFIG_SET_BINARY) {
        payload_size += capture_fs_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            3,
            ctx->args[3],
            ctx->args[4],
            event_flags);
        return payload_size;
    }
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        3,
        ctx->args[3],
        FS_DIRECT_FSCONFIG_VALUE_MAX);
    return payload_size;
}

static __always_inline u32 capture_fs_enter_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (sys_id == SYS_MOUNT) {
        return capture_mount_payload_tlv_direct(ptr, payload_offset, ctx);
    }
    if (sys_id == SYS_UMOUNT2) {
        return capture_fs_string_tlv_direct(
            ptr,
            payload_offset,
            0,
            ctx->args[0],
            FS_DIRECT_MOUNT_STRING_MAX);
    }
    if (sys_id == SYS_FSCONFIG) {
        return capture_fsconfig_payload_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    if (sys_id == SYS_MOUNT_SETATTR) {
        return capture_mount_setattr_enter_payload_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    if (is_mount_query_direct_syscall(sys_id)) {
        return capture_mnt_id_req_enter_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    return 0;
}

static __always_inline u32 capture_getdents_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    if (ret_value <= 0) {
        return 0;
    }

    u64 user_ptr = p->args[1];
    u32 user_len = payload_tlv_clamp_u32((u64)ret_value);
    u32 copied_len = payload_tlv_copy_len((u64)ret_value, FS_DIRECT_GETDENTS_BYTES_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
        copied_len = 0;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_GETDENTS_BYTES_MAX);
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
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
