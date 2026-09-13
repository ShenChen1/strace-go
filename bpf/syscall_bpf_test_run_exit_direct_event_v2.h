#ifndef STRACE_GO_SYSCALL_BPF_TEST_RUN_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_TEST_RUN_EXIT_DIRECT_EVENT_V2_H

struct bpf_test_run_output_spec {
    u32 size_offset;
    u32 ptr_offset;
    u16 arg_index;
};

static __always_inline int read_bpf_test_run_output_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_test_run_output_spec *spec,
    struct bpf_exit_bytes_request *request)
{
    u32 user_len = 0;
    u64 user_ptr = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr, attr_size, spec->size_offset, &user_len) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, spec->ptr_offset, &user_ptr) ||
        !user_ptr || !user_len) {
        return 0;
    }
    request->user_ptr = user_ptr;
    request->user_len = user_len;
    request->max_len = BPF_DIRECT_TEST_RUN_OUTPUT_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = spec->arg_index;
    return 1;
}

static __always_inline u32 capture_bpf_test_run_outputs_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_exit_bytes_request *data_request,
    struct bpf_exit_bytes_request *ctx_request,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (data_request->user_ptr && data_request->user_len) {
        payload_size += capture_bpf_exit_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            data_request,
            event_flags);
    }
    if (ctx_request->user_ptr && ctx_request->user_len) {
        payload_size += capture_bpf_exit_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            ctx_request,
            event_flags);
    }
    return payload_size;
}

static __always_inline int emit_bpf_prog_test_run_record_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    struct bpf_exit_bytes_request *data_request,
    struct bpf_exit_bytes_request *ctx_request)
{
    u32 payload_capacity = 2 *
        (PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_TEST_RUN_OUTPUT_MAX);
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
        return 1;
    }

    u16 flags = 0;
    u32 payload_size = capture_bpf_test_run_outputs_direct(
        &ptr,
        payload_offset,
        data_request,
        ctx_request,
        &flags);
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
        return 1;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 1;
}

static __always_inline int emit_bpf_prog_test_run_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_PROG_TEST_RUN ||
        ret_value != 0) {
        return 0;
    }

    struct bpf_test_run_output_spec data_spec = {
        .size_offset = BPF_DIRECT_TEST_RUN_DATA_SIZE_OUT_OFF,
        .ptr_offset = BPF_DIRECT_TEST_RUN_DATA_OUT_OFF,
        .arg_index = BPF_DIRECT_TEST_RUN_DATA_ARG,
    };
    struct bpf_test_run_output_spec ctx_spec = {
        .size_offset = BPF_DIRECT_TEST_RUN_CTX_SIZE_OUT_OFF,
        .ptr_offset = BPF_DIRECT_TEST_RUN_CTX_OUT_OFF,
        .arg_index = BPF_DIRECT_TEST_RUN_CTX_ARG,
    };
    struct bpf_exit_bytes_request data_request = {};
    struct bpf_exit_bytes_request ctx_request = {};
    (void)read_bpf_test_run_output_request_direct(
        p->args[1], p->args[2], &data_spec, &data_request);
    (void)read_bpf_test_run_output_request_direct(
        p->args[1], p->args[2], &ctx_spec, &ctx_request);
    if ((!data_request.user_ptr || !data_request.user_len) &&
        (!ctx_request.user_ptr || !ctx_request.user_len)) {
        return 0;
    }
    return emit_bpf_prog_test_run_record_v2_direct(
        p,
        ret_value,
        duration,
        &data_request,
        &ctx_request);
}

#endif
