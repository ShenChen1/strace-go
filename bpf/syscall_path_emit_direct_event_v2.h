#ifndef STRACE_GO_SYSCALL_PATH_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PATH_EMIT_DIRECT_EVENT_V2_H

struct path_only_emit_request {
    u16 path_arg;
    u64 user_ptr;
};

struct dual_path_emit_request {
    u16 first_arg;
    u16 second_arg;
    u64 first_ptr;
    u64 second_ptr;
};

static __always_inline void emit_path_only_enter_event_v2_direct_with_path(
    u32 pid,
    u32 tid,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    const struct path_only_emit_request *request)
{
    u32 sys_id = (u32)ctx->id;
    u16 path_arg = request->path_arg;
    u64 user_ptr = request->user_ptr;
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_path_only_tlv_direct(&ptr, payload_offset, path_arg, user_ptr);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
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

static __always_inline void emit_path_only_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct path_only_emit_request request = {};
    if (is_path_only_arg1_direct_syscall(sys_id)) {
        request.path_arg = 1;
        request.user_ptr = ctx->args[1];
        emit_path_only_enter_event_v2_direct_with_path(pid, tid, ctx, ts_ns, &request);
        return;
    }
    request.path_arg = 0;
    request.user_ptr = ctx->args[0];
    emit_path_only_enter_event_v2_direct_with_path(pid, tid, ctx, ts_ns, &request);
}

static __always_inline void emit_path_only_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u16 path_arg = 0;
    if (is_path_only_arg1_direct_syscall(p->sys_id)) {
        path_arg = 1;
    }

    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_path_only_tlv_direct(&ptr, payload_offset, path_arg, p->args[path_arg]);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
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

static __always_inline void emit_dual_path_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u16 first_arg = 0;
    u16 second_arg = 1;
    u64 first_ptr = p->args[0];
    u64 second_ptr = p->args[1];
    if (is_dual_path_0_2_direct_syscall(p->sys_id)) {
        second_arg = 2;
        second_ptr = p->args[2];
    } else if (is_dual_path_1_3_direct_syscall(p->sys_id)) {
        first_arg = 1;
        first_ptr = p->args[1];
        second_arg = 3;
        second_ptr = p->args[3];
    }

    u32 payload_capacity = 2 * (PAYLOAD_TLV_HEADER_SIZE + DUAL_PATH_DIRECT_PATH_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_dual_path_tlv_direct(
        &ptr,
        payload_offset,
        first_arg,
        first_ptr);
    payload_size += capture_dual_path_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        second_arg,
        second_ptr);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
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

static __always_inline void emit_dual_path_enter_event_v2_direct_with_paths(
    u32 pid,
    u32 tid,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    const struct dual_path_emit_request *request)
{
    u32 sys_id = (u32)ctx->id;
    u16 first_arg = request->first_arg;
    u16 second_arg = request->second_arg;
    u64 first_ptr = request->first_ptr;
    u64 second_ptr = request->second_ptr;
    u32 payload_capacity = 2 * (PAYLOAD_TLV_HEADER_SIZE + DUAL_PATH_DIRECT_PATH_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_dual_path_tlv_direct(&ptr, payload_offset, first_arg, first_ptr);
    payload_size += capture_dual_path_tlv_direct(&ptr, payload_offset + payload_size, second_arg, second_ptr);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
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

static __always_inline void emit_dual_path_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct dual_path_emit_request request = {};
    if (is_dual_path_0_2_direct_syscall(sys_id)) {
        request.first_arg = 0;
        request.second_arg = 2;
        request.first_ptr = ctx->args[0];
        request.second_ptr = ctx->args[2];
        emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, ctx, ts_ns, &request);
        return;
    }
    if (is_dual_path_1_3_direct_syscall(sys_id)) {
        request.first_arg = 1;
        request.second_arg = 3;
        request.first_ptr = ctx->args[1];
        request.second_ptr = ctx->args[3];
        emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, ctx, ts_ns, &request);
        return;
    }
    request.first_arg = 0;
    request.second_arg = 1;
    request.first_ptr = ctx->args[0];
    request.second_ptr = ctx->args[1];
    emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, ctx, ts_ns, &request);
}

#endif
