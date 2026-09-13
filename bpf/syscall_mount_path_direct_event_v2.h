#ifndef STRACE_GO_SYSCALL_MOUNT_PATH_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MOUNT_PATH_DIRECT_EVENT_V2_H

#define MOUNT_PATH_DIRECT_PAYLOAD_CAPACITY \
    (2 * (PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX))

static __always_inline int is_mount_path_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_MOVE_MOUNT;
}

static __always_inline void emit_mount_path_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MOUNT_PATH_DIRECT_PAYLOAD_CAPACITY;
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
    u32 payload_size = capture_path_only_tlv_direct(
        &ptr, payload_offset, 1, ctx->args[1]);
    payload_size += capture_path_only_tlv_direct(
        &ptr, payload_offset + payload_size, 3, ctx->args[3]);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
    init_syscall_event_v2_header_direct(
        &header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
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

#endif
