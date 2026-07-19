#ifndef STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H

#define SELECT_DIRECT_FDSET_SIZE 128
#define SELECT_DIRECT_TIMEVAL_SIZE 16
#define SELECT_DIRECT_FDSET_ARG_BASE 1
#define SELECT_DIRECT_FDSET_ARG_LAST 3
#define SELECT_DIRECT_PAYLOAD_MAX (3 * (PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_FDSET_SIZE) + PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_TIMEVAL_SIZE)

static __always_inline int is_select_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SELECT;
}

static __always_inline u32 select_direct_fdset_user_len(u64 nfds_raw)
{
    s32 nfds = (s32)nfds_raw;
    if (nfds <= 0) {
        return 0;
    }
    if (nfds > SELECT_DIRECT_FDSET_SIZE * 8) {
        return SELECT_DIRECT_FDSET_SIZE;
    }
    return (u32)((nfds + 7) / 8);
}

static __always_inline long select_direct_read_fdset_small(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len == 1) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 1);
        return payload_data ? bpf_probe_read_user(payload_data, 1, (void *)user_ptr) : -1;
    }
    if (user_len == 2) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 2);
        return payload_data ? bpf_probe_read_user(payload_data, 2, (void *)user_ptr) : -1;
    }
    if (user_len == 3) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 3);
        return payload_data ? bpf_probe_read_user(payload_data, 3, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, 4);
    return payload_data ? bpf_probe_read_user(payload_data, 4, (void *)user_ptr) : -1;
}

static __always_inline long select_direct_read_fdset_medium(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len == 5) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 5);
        return payload_data ? bpf_probe_read_user(payload_data, 5, (void *)user_ptr) : -1;
    }
    if (user_len == 6) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 6);
        return payload_data ? bpf_probe_read_user(payload_data, 6, (void *)user_ptr) : -1;
    }
    if (user_len == 7) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 7);
        return payload_data ? bpf_probe_read_user(payload_data, 7, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, 8);
    return payload_data ? bpf_probe_read_user(payload_data, 8, (void *)user_ptr) : -1;
}

static __always_inline long select_direct_read_fdset_wide(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len <= 16) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 16);
        return payload_data ? bpf_probe_read_user(payload_data, 16, (void *)user_ptr) : -1;
    }
    if (user_len <= 32) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 32);
        return payload_data ? bpf_probe_read_user(payload_data, 32, (void *)user_ptr) : -1;
    }
    if (user_len <= 64) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 64);
        return payload_data ? bpf_probe_read_user(payload_data, 64, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, SELECT_DIRECT_FDSET_SIZE);
    return payload_data ? bpf_probe_read_user(payload_data, SELECT_DIRECT_FDSET_SIZE, (void *)user_ptr) : -1;
}

static __always_inline u32 capture_select_fdset_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 nfds,
    u16 tlv_flags)
{
    u32 user_len = select_direct_fdset_user_len(nfds);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    u32 copied_len = user_len;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    long err = 0;
    if (user_len <= 4) {
        err = select_direct_read_fdset_small(ptr, data_offset, user_ptr, user_len);
    } else if (user_len <= 8) {
        err = select_direct_read_fdset_medium(ptr, data_offset, user_ptr, user_len);
    } else {
        err = select_direct_read_fdset_wide(ptr, data_offset, user_ptr, user_len);
    }
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
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

static __always_inline u32 capture_select_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = SELECT_DIRECT_TIMEVAL_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, SELECT_DIRECT_TIMEVAL_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, SELECT_DIRECT_TIMEVAL_SIZE, (void *)user_ptr);
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
            SELECT_DIRECT_TIMEVAL_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_select_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 *args,
    u16 tlv_flags,
    int include_fdsets,
    int include_timeout)
{
    u32 payload_size = 0;
    if (include_fdsets) {
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            SELECT_DIRECT_FDSET_ARG_BASE,
            args[1],
            args[0],
            tlv_flags);
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            2,
            args[2],
            args[0],
            tlv_flags);
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            SELECT_DIRECT_FDSET_ARG_LAST,
            args[3],
            args[0],
            tlv_flags);
    }
    if (include_timeout) {
        payload_size += capture_select_timeout_tlv_direct(
            ptr,
            payload_offset + payload_size,
            args[4],
            tlv_flags);
    }
    return payload_size;
}

static __always_inline void emit_select_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + SELECT_DIRECT_PAYLOAD_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_select_payloads_tlv_direct(
        &ptr,
        payload_offset,
        body.args,
        0,
        1,
        1);
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

    body.capture_len = payload_size;
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_select_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + SELECT_DIRECT_PAYLOAD_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_select_payloads_tlv_direct(
        &ptr,
        payload_offset,
        p->args,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        ret_value > 0,
        1);
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

#endif
