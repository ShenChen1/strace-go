#ifndef STRACE_GO_SYSCALL_XATTR_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_XATTR_DIRECT_EVENT_V2_H

#define XATTR_DIRECT_PATH_MAX 512
#define XATTR_DIRECT_NAME_MAX 256
#define XATTR_DIRECT_VALUE_MAX 256
#define XATTR_DIRECT_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + XATTR_DIRECT_PATH_MAX + XATTR_DIRECT_NAME_MAX + XATTR_DIRECT_VALUE_MAX)

static __always_inline int is_xattr_set_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETXATTR || sys_id == SYS_LSETXATTR ||
        sys_id == SYS_FSETXATTR;
}

static __always_inline int is_xattr_get_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETXATTR || sys_id == SYS_LGETXATTR ||
        sys_id == SYS_FGETXATTR;
}

static __always_inline int is_xattr_list_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_LISTXATTR || sys_id == SYS_LLISTXATTR ||
        sys_id == SYS_FLISTXATTR;
}

static __always_inline int is_xattr_remove_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_REMOVEXATTR || sys_id == SYS_LREMOVEXATTR ||
        sys_id == SYS_FREMOVEXATTR;
}

static __always_inline int is_xattr_direct_syscall(u32 sys_id)
{
    return is_xattr_set_direct_syscall(sys_id) ||
        is_xattr_get_direct_syscall(sys_id) ||
        is_xattr_list_direct_syscall(sys_id) ||
        is_xattr_remove_direct_syscall(sys_id);
}

static __always_inline int xattr_direct_has_path(u32 sys_id)
{
    return sys_id == SYS_SETXATTR || sys_id == SYS_LSETXATTR ||
        sys_id == SYS_GETXATTR || sys_id == SYS_LGETXATTR ||
        sys_id == SYS_LISTXATTR || sys_id == SYS_LLISTXATTR ||
        sys_id == SYS_REMOVEXATTR || sys_id == SYS_LREMOVEXATTR;
}

static __always_inline int xattr_direct_has_name(u32 sys_id)
{
    return is_xattr_set_direct_syscall(sys_id) ||
        is_xattr_get_direct_syscall(sys_id) ||
        is_xattr_remove_direct_syscall(sys_id);
}

static __always_inline u32 capture_xattr_string_tlv_direct(
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
    if (max_len == XATTR_DIRECT_PATH_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, XATTR_DIRECT_PATH_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, XATTR_DIRECT_NAME_MAX);
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

static __always_inline u32 capture_xattr_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_user_len,
    u16 tlv_flags,
    u16 *event_flags)
{
    u32 user_len = payload_tlv_clamp_u32(raw_user_len);
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(raw_user_len, XATTR_DIRECT_VALUE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, XATTR_DIRECT_VALUE_MAX);
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

    if (event_flags && probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            arg_index,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_xattr_enter_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (xattr_direct_has_path(sys_id)) {
        payload_size += capture_xattr_string_tlv_direct(
            ptr,
            payload_offset + payload_size,
            0,
            ctx->args[0],
            XATTR_DIRECT_PATH_MAX);
    }
    if (xattr_direct_has_name(sys_id)) {
        payload_size += capture_xattr_string_tlv_direct(
            ptr,
            payload_offset + payload_size,
            1,
            ctx->args[1],
            XATTR_DIRECT_NAME_MAX);
    }
    if (is_xattr_set_direct_syscall(sys_id)) {
        payload_size += capture_xattr_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            2,
            ctx->args[2],
            ctx->args[3],
            0,
            event_flags);
    }
    return payload_size;
}

static __always_inline void emit_xattr_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = XATTR_DIRECT_PAYLOAD_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_xattr_enter_payload_tlv_direct(&ptr, payload_offset, sys_id, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_xattr_bytes_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    u16 arg_index,
    u64 user_ptr)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + XATTR_DIRECT_VALUE_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_xattr_bytes_tlv_direct(
        &ptr,
        payload_offset,
        arg_index,
        user_ptr,
        (u64)ret_value,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_xattr_get_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    emit_xattr_bytes_exit_event_v2_direct(p, ret_value, duration, 2, p->args[2]);
}

static __always_inline void emit_xattr_list_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    emit_xattr_bytes_exit_event_v2_direct(p, ret_value, duration, 1, p->args[1]);
}

#endif
