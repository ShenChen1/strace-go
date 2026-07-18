#ifndef STRACE_GO_SYSCALL_FUTEX_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FUTEX_DIRECT_EVENT_V2_H

#define FUTEX_DIRECT_CMD_MASK 0x7f
#define FUTEX_DIRECT_WAIT 0
#define FUTEX_DIRECT_LOCK_PI 6
#define FUTEX_DIRECT_WAIT_BITSET 9
#define FUTEX_DIRECT_WAIT_REQUEUE_PI 11
#define FUTEX_DIRECT_LOCK_PI2 13
#define FUTEX_DIRECT_WAITV_ELEM_SIZE 24
#define FUTEX_DIRECT_WAITV_MAX 128
#define FUTEX_DIRECT_WAITV_MAX_BYTES 3072
#define FUTEX_DIRECT_REQUEUE_WAITERS_SIZE 48

static __always_inline int futex_has_timeout_direct(u64 op)
{
    u64 base_op = op & FUTEX_DIRECT_CMD_MASK;
    return base_op == FUTEX_DIRECT_WAIT ||
        base_op == FUTEX_DIRECT_LOCK_PI ||
        base_op == FUTEX_DIRECT_WAIT_BITSET ||
        base_op == FUTEX_DIRECT_WAIT_REQUEUE_PI ||
        base_op == FUTEX_DIRECT_LOCK_PI2;
}

static __always_inline void emit_futex_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE;
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
    if (futex_has_timeout_direct(ctx->args[1])) {
        payload_size = capture_time_struct_tlv_direct_from_ptr(
            &ptr,
            payload_offset,
            3,
            ctx->args[3],
            TIME_DIRECT_TIMESPEC_SIZE,
            0);
    }
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

static __always_inline void emit_futex_wait_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE;
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
    u32 payload_size = capture_time_struct_tlv_direct_from_ptr(
        &ptr,
        payload_offset,
        4,
        ctx->args[4],
        TIME_DIRECT_TIMESPEC_SIZE,
        0);
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

static __always_inline u32 capture_futex_requeue_waiters_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = FUTEX_DIRECT_REQUEUE_WAITERS_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FUTEX_DIRECT_REQUEUE_WAITERS_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, FUTEX_DIRECT_REQUEUE_WAITERS_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            0,
            0,
            FUTEX_DIRECT_REQUEUE_WAITERS_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 futex_waitv_user_len_direct(u32 count)
{
    if (count > 0xffffffffU / FUTEX_DIRECT_WAITV_ELEM_SIZE) {
        return 0xffffffffU;
    }
    return (u32)(count * FUTEX_DIRECT_WAITV_ELEM_SIZE);
}

static __always_inline u32 futex_waitv_copy_len_direct(u32 count)
{
    if (count > FUTEX_DIRECT_WAITV_MAX) {
        count = FUTEX_DIRECT_WAITV_MAX;
    }
    return (u32)count * FUTEX_DIRECT_WAITV_ELEM_SIZE;
}

static __always_inline u32 capture_futex_waitv_waiters_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 count,
    u16 *event_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 user_len = futex_waitv_user_len_direct(count);
    u32 requested_len = futex_waitv_copy_len_direct(count);
    if (requested_len == 0) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = FUTEX_DIRECT_WAITV_ELEM_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FUTEX_DIRECT_WAITV_ELEM_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, FUTEX_DIRECT_WAITV_ELEM_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        } else if (requested_len > FUTEX_DIRECT_WAITV_ELEM_SIZE) {
            u32 rest_len = requested_len - FUTEX_DIRECT_WAITV_ELEM_SIZE;
            void *payload_rest = bpf_dynptr_data(
                ptr,
                data_offset + FUTEX_DIRECT_WAITV_ELEM_SIZE,
                FUTEX_DIRECT_WAITV_MAX_BYTES - FUTEX_DIRECT_WAITV_ELEM_SIZE);
            if (!payload_rest) {
                record_ringbuf_copy_fail();
            } else {
                long rest_err = bpf_probe_read_user(
                    payload_rest,
                    rest_len,
                    (void *)(user_ptr + FUTEX_DIRECT_WAITV_ELEM_SIZE));
                if (rest_err == 0) {
                    copied_len = requested_len;
                }
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && requested_len < user_len) {
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

static __always_inline void emit_futex_waitv_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + FUTEX_DIRECT_WAITV_MAX_BYTES +
        PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE;
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
    u32 payload_size = capture_futex_waitv_waiters_tlv_direct(
        &ptr,
        payload_offset,
        ctx->args[0],
        (u32)ctx->args[1],
        &flags);
    payload_size += capture_time_struct_tlv_direct_from_ptr(
        &ptr,
        payload_offset + payload_size,
        3,
        ctx->args[3],
        TIME_DIRECT_TIMESPEC_SIZE,
        0);
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

static __always_inline void emit_futex_requeue_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + FUTEX_DIRECT_REQUEUE_WAITERS_SIZE;
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
    u32 payload_size = capture_futex_requeue_waiters_tlv_direct(&ptr, payload_offset, ctx->args[0]);
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
