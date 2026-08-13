#ifndef STRACE_GO_SYSCALL_AIO_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_EMIT_DIRECT_EVENT_V2_H

static __always_inline void emit_aio_submit_iovec_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset +
        AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX * (PAYLOAD_TLV_HEADER_SIZE +
                                             AIO_SUBMIT_DIRECT_IOVEC_MAX * AIO_SUBMIT_DIRECT_IOVEC_SIZE);
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_aio_submit_iocbs_iovec_tlv_direct(&ptr, payload_offset, ctx);
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

static __always_inline void emit_aio_submit_buf_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset +
        AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX * (PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_BUF_MAX);
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_aio_submit_iocbs_buf_tlv_direct(&ptr, payload_offset, ctx);
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

static __always_inline void emit_aio_submit_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + AIO_SUBMIT_DIRECT_MAX_PAYLOAD;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_aio_submit_pointers_tlv_direct(&ptr, payload_offset, ctx);
    payload_size += capture_aio_submit_iocbs_tlv_direct(&ptr, payload_offset + payload_size, ctx);
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

static __always_inline void emit_aio_cancel_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + AIO_CANCEL_DIRECT_IOCB_SIZE;
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
    u32 payload_size = capture_aio_cancel_iocb_tlv_direct(&ptr, payload_offset, ctx->args[1]);
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

static __always_inline void emit_aio_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    if (is_aio_pgetevents_direct_syscall(sys_id)) {
        emit_aio_pgetevents_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    if (is_aio_getevents_direct_syscall(sys_id)) {
        emit_aio_getevents_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    if (is_aio_submit_direct_syscall(sys_id)) {
        emit_aio_submit_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    if (is_aio_cancel_direct_syscall(sys_id)) {
        emit_aio_cancel_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, ts_ns);
}

static __always_inline void emit_aio_setup_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + AIO_SETUP_DIRECT_CTX_SIZE;
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
    u32 payload_size = 0;
    if (ret_value >= 0) {
        payload_size = capture_aio_setup_ctx_tlv_direct(&ptr, payload_offset, p->args[1]);
    }
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
