#ifndef STRACE_GO_SYSCALL_READLINK_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_READLINK_EMIT_DIRECT_EVENT_V2_H

struct readlink_enter_request {
    u64 args[6];
    u16 path_arg;
    u64 user_ptr;
};

static __always_inline void emit_readlink_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct readlink_enter_request request = {};
    request.args[0] = ctx->args[0];
    request.args[1] = ctx->args[1];
    request.args[2] = ctx->args[2];
    request.args[3] = ctx->args[3];
    request.args[4] = ctx->args[4];
    request.args[5] = ctx->args[5];
    request.path_arg = 0;
    request.user_ptr = request.args[0];
    if (sys_id == SYS_READLINKAT) {
        request.path_arg = 1;
        request.user_ptr = request.args[1];
    }

    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + READLINK_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    body.ret = 0;
    body.probe_ret_enter = -1;
    body.probe_ret_exit = -1;
    body.args[0] = request.args[0];
    body.args[1] = request.args[1];
    body.args[2] = request.args[2];
    body.args[3] = request.args[3];
    body.args[4] = request.args[4];
    body.args[5] = request.args[5];
    body.capture_len = 0;
    body.capture_flags = 0;

    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_readlink_path_tlv_direct(
        &ptr, payload_offset, request.path_arg, request.user_ptr);
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

static __always_inline void emit_readlink_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + READLINK_DIRECT_BYTES_MAX;
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
    u32 payload_size = capture_readlink_bytes_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
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
