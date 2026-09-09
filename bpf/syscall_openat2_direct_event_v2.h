#ifndef STRACE_GO_SYSCALL_OPENAT2_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_OPENAT2_DIRECT_EVENT_V2_H

#define OPENAT2_DIRECT_PATH_MAX 4096
#define OPENAT2_DIRECT_HOW_MIN 24
#define OPENAT2_DIRECT_HOW_MAX 64
#define OPENAT2_DIRECT_PAYLOAD_CAPACITY \
    (2 * PAYLOAD_TLV_HEADER_SIZE + OPENAT2_DIRECT_PATH_MAX + OPENAT2_DIRECT_HOW_MAX)
#define OPENAT2_DIRECT_FD_PATH_CAPACITY FD_PATH_DIRECT_SECTION_MAX
#define OPENAT2_DIRECT_EXIT_PAYLOAD_CAPACITY \
    (OPENAT2_DIRECT_PAYLOAD_CAPACITY + PAYLOAD_TLV_HEADER_SIZE + FD_STATE_SNAPSHOT_SIZE)

static __always_inline int is_openat2_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_OPENAT2;
}

static __always_inline u32 capture_openat2_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, OPENAT2_DIRECT_PATH_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, OPENAT2_DIRECT_PATH_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > OPENAT2_DIRECT_PATH_MAX) {
                copied_len = OPENAT2_DIRECT_PATH_MAX;
            } else {
                copied_len = (u32)n;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            1,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_openat2_how_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 requested_len,
    u16 *event_flags)
{
    if (!user_ptr || requested_len < OPENAT2_DIRECT_HOW_MIN) {
        return 0;
    }

    u32 user_len = payload_tlv_clamp_u32(requested_len);
    u32 copied_len = OPENAT2_DIRECT_HOW_MIN;
    u32 wanted_len = payload_tlv_copy_len(requested_len, OPENAT2_DIRECT_HOW_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, OPENAT2_DIRECT_HOW_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, OPENAT2_DIRECT_HOW_MIN, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        } else if (wanted_len > OPENAT2_DIRECT_HOW_MIN) {
            u32 extra_len = wanted_len - OPENAT2_DIRECT_HOW_MIN;
            long extra_err = bpf_probe_read_user(
                (void *)((char *)payload_data + OPENAT2_DIRECT_HOW_MIN),
                extra_len,
                (void *)(user_ptr + OPENAT2_DIRECT_HOW_MIN));
            if (extra_err == 0) {
                copied_len = wanted_len;
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
            PAYLOAD_TLV_KIND_STRUCT,
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

static __always_inline void emit_openat2_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    u32 fd_path_capacity = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        fd_path_capacity = OPENAT2_DIRECT_FD_PATH_CAPACITY;
    }
    u32 payload_capacity = fd_path_capacity + OPENAT2_DIRECT_PAYLOAD_CAPACITY;
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
    u32 payload_size = 0;
    if (fd_path_capacity > 0) {
        payload_size = capture_fd_path_tlv_direct(
            &ptr,
            payload_offset,
            0,
            (s32)ctx->args[0]);
    }
    payload_size += capture_openat2_path_tlv_direct(&ptr, payload_offset + payload_size, ctx->args[1]);
    payload_size += capture_openat2_how_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        ctx->args[2],
        ctx->args[3],
        &flags);
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

static __always_inline void emit_openat2_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = OPENAT2_DIRECT_EXIT_PAYLOAD_CAPACITY;
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
    u32 payload_size = capture_openat2_path_tlv_direct(
        &ptr,
        payload_offset,
        p->args[1]);
    payload_size += capture_openat2_how_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        p->args[2],
        p->args[3],
        &flags);
    if (ret_value >= 0) {
        payload_size += capture_fd_state_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            (s32)ret_value);
    }
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
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

#endif
