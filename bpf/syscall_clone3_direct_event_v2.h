#ifndef STRACE_GO_SYSCALL_CLONE3_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_CLONE3_DIRECT_EVENT_V2_H

#define CLONE3_DIRECT_ARGS_MAX 256
#define CLONE3_DIRECT_SET_TID_MAX_ENTRIES 32
#define CLONE3_DIRECT_SET_TID_BYTES_MAX \
    (CLONE3_DIRECT_SET_TID_MAX_ENTRIES * sizeof(s32))

static __always_inline u32 capture_clone3_set_tid_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args_ptr,
    u64 args_len)
{
    if (!args_ptr || args_len < 80 || args_ptr > 0xffffffffffffffffULL - 80) {
        return 0;
    }

    u64 set_tid_ptr = 0;
    u64 set_tid_size = 0;
    if (bpf_probe_read_user(&set_tid_ptr, sizeof(set_tid_ptr),
                            (void *)(args_ptr + 64)) != 0 ||
        bpf_probe_read_user(&set_tid_size, sizeof(set_tid_size),
                            (void *)(args_ptr + 72)) != 0 ||
        !set_tid_ptr || set_tid_size == 0 ||
        set_tid_size > CLONE3_DIRECT_SET_TID_MAX_ENTRIES) {
        return 0;
    }

    u32 user_len = (u32)set_tid_size * sizeof(s32);
    if (set_tid_ptr > 0xffffffffffffffffULL - user_len) {
        return 0;
    }
    u32 copied_len = user_len;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr, data_offset, CLONE3_DIRECT_SET_TID_BYTES_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len,
                                       (void *)set_tid_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            PAYLOAD_TLV_CLONE3_SET_TID_ARG_INDEX,
            0,
            user_len,
            copied_len,
            probe_ret,
            set_tid_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline int is_clone3_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CLONE3;
}

static __always_inline u32 capture_clone3_args_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 requested_len,
    u16 *event_flags)
{
    if (!user_ptr || requested_len == 0) {
        return 0;
    }

    u32 user_len = payload_tlv_clamp_u32(requested_len);
    u32 copied_len = payload_tlv_copy_len(requested_len, CLONE3_DIRECT_ARGS_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, CLONE3_DIRECT_ARGS_MAX);
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
            PAYLOAD_TLV_KIND_STRUCT,
            0,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_clone3_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + CLONE3_DIRECT_ARGS_MAX +
        PAYLOAD_TLV_HEADER_SIZE + CLONE3_DIRECT_SET_TID_BYTES_MAX;
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
    u32 payload_size = capture_clone3_args_tlv_direct(&ptr, payload_offset, ctx->args[0], ctx->args[1], &flags);
    payload_size += capture_clone3_set_tid_tlv_direct(
        &ptr, payload_offset + payload_size, ctx->args[0], ctx->args[1]);
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

#endif
