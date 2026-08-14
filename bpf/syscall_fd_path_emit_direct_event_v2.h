#ifndef STRACE_GO_SYSCALL_FD_PATH_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_PATH_EMIT_DIRECT_EVENT_V2_H

static __always_inline void emit_fd_path_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return;
    }
    copy_syscall_enter_args(scratch->args, ctx);
    u32 payload_capacity = fd_path_payload_capacity(sys_id);
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
    u32 payload_size = capture_fd_paths_tlv_direct(&ptr, payload_offset, sys_id, scratch->args);
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
    init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_fd_path_or_no_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    u32 sys_id = (u32)ctx->id;
    if (!cfg || !(*cfg & CONFIG_EMIT_ENTER)) {
        return;
    }
    if ((*cfg & CONFIG_FD_STATE) && fd_path_arg_count(sys_id) > 0) {
        emit_fd_path_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    emit_syscall_enter_event_v2_direct(pid, tid, sys_id, ctx, EVENT_FLAG_GENERIC_ENTER, ts_ns);
}

static __always_inline void emit_nested_fd_path_fragment_event_v2_direct(
    struct pending_syscall *p,
    s32 fd)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + FD_PATH_DIRECT_SECTION_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u32 payload_size = capture_fd_path_tlv_direct(
        &ptr,
        payload_offset,
        PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX,
        fd);
    u16 flags = EVENT_FLAG_EXIT_FRAGMENT;
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
        bpf_ktime_get_ns());
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, 0, 0, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
