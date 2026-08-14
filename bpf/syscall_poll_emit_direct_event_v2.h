#ifndef STRACE_GO_SYSCALL_POLL_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_POLL_EMIT_DIRECT_EVENT_V2_H

static __always_inline void emit_poll_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_FDS_MAX;
    if (is_ppoll_direct_syscall(sys_id)) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_TIMEOUT_SIZE;
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_SIGMASK_SIZE;
    }
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
    struct poll_fd_capture_request fd_request = {};
    fd_request.user_ptr = ctx->args[0];
    fd_request.count = poll_direct_count(sys_id, ctx->args[1]);
    fd_request.tlv_flags = 0;
    u32 payload_size = capture_poll_fds_tlv_direct(&ptr, payload_offset, &fd_request, &flags);
    if (is_ppoll_direct_syscall(sys_id)) {
        payload_size += capture_poll_timeout_tlv_direct(&ptr, payload_offset + payload_size, ctx->args[2], 0);
        payload_size += capture_poll_sigmask_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            ctx->args[3],
            ctx->args[4]);
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

static __always_inline void emit_poll_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_FDS_MAX;
    if (is_ppoll_direct_syscall(p->sys_id)) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_TIMEOUT_SIZE;
    }
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
    struct poll_fd_capture_request fd_request = {};
    fd_request.user_ptr = p->args[0];
    fd_request.count = poll_direct_count(p->sys_id, p->args[1]);
    fd_request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
    u32 payload_size = capture_poll_fds_tlv_direct(&ptr, payload_offset, &fd_request, &flags);
    if (is_ppoll_direct_syscall(p->sys_id)) {
        payload_size += capture_poll_timeout_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            p->args[2],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
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
