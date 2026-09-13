#ifndef STRACE_GO_SYSCALL_BPF_TRACING_MULTI_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_TRACING_MULTI_DIRECT_EVENT_V2_H

#define BPF_DIRECT_TRACING_MULTI_CAPACITY \
    (2 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_MULTI_U32_ARRAY_MAX + BPF_DIRECT_MULTI_U64_ARRAY_MAX)

static __noinline int is_bpf_tracing_multi_enter_direct(
    struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->args[0] != BPF_DIRECT_LINK_CREATE) {
        return 0;
    }
    u32 attach_type = 0;
    if (!bpf_attr_read_u32_direct(
            ctx->args[1],
            ctx->args[2],
            BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF,
            &attach_type)) {
        return 0;
    }
    return attach_type == BPF_DIRECT_TRACE_FENTRY_MULTI_ATTACH ||
           attach_type == BPF_DIRECT_TRACE_FEXIT_MULTI_ATTACH ||
           attach_type == BPF_DIRECT_TRACE_FSESSION_MULTI_ATTACH;
}

// Capture tracing_multi arrays with their native element widths and a bounded prefix.
static __noinline u32 capture_bpf_tracing_multi_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 attach_type = 0;
    u64 ids = 0;
    u64 cookies = 0;
    u32 count = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF, &attach_type) ||
        (attach_type != BPF_DIRECT_TRACE_FENTRY_MULTI_ATTACH &&
         attach_type != BPF_DIRECT_TRACE_FEXIT_MULTI_ATTACH &&
         attach_type != BPF_DIRECT_TRACE_FSESSION_MULTI_ATTACH) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_TRACING_MULTI_IDS_OFF, &ids) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_TRACING_MULTI_COOKIES_OFF, &cookies) ||
        !bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_TRACING_MULTI_CNT_OFF, &count)) {
        return 0;
    }

    struct bpf_multi_u32_array_capture_request ids_request = {
        .user_ptr = ids,
        .count = count,
        .arg_index = BPF_DIRECT_TRACING_MULTI_IDS_ARG,
        .event_flags = event_flags,
    };
    struct bpf_multi_u64_array_capture_request cookies_request = {
        .user_ptr = cookies,
        .count = count,
        .arg_index = BPF_DIRECT_TRACING_MULTI_COOKIES_ARG,
        .event_flags = event_flags,
    };
    u32 payload_size = capture_bpf_multi_u32_array_tlv_direct(
        ptr,
        payload_offset,
        &ids_request);
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &cookies_request);
    return payload_size;
}

static __noinline void emit_bpf_tracing_multi_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 attr_ptr = ctx->args[1];
    u64 attr_size = ctx->args[2];
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_ATTR_MAX + BPF_DIRECT_TRACING_MULTI_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_bpf_attr_tlv_direct(&ptr, payload_offset, attr_ptr, attr_size, &flags);
    payload_size += capture_bpf_tracing_multi_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header *header = event_v2_header_from_dynptr_direct(&ptr, sequence);
    if (!header) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    init_syscall_event_v2_header_direct(header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);

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
