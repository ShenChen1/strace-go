#ifndef STRACE_GO_SYSCALL_BPF_PROG_QUERY_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_PROG_QUERY_EXIT_DIRECT_EVENT_V2_H

#define BPF_DIRECT_PROG_QUERY_ARRAY_ELEM_SIZE 4
#define BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS 5

static __always_inline u32 bpf_prog_query_array_len_direct(u32 count)
{
    u64 total = (u64)count * BPF_DIRECT_PROG_QUERY_ARRAY_ELEM_SIZE;
    if (total > 0xffffffffULL) {
        return 0xffffffffU;
    }
    return (u32)total;
}

static __always_inline void set_bpf_prog_query_array_request_direct(
    struct bpf_exit_bytes_request *request,
    u64 user_ptr,
    u32 user_len,
    u16 arg_index)
{
    if (!user_ptr || user_len == 0) {
        return;
    }
    request->user_ptr = user_ptr;
    request->user_len = user_len;
    request->max_len = BPF_DIRECT_PROG_QUERY_ARRAY_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = arg_index;
}

static __always_inline int read_bpf_prog_query_output_requests_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_exit_bytes_request requests[BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS])
{
    u32 prog_cnt = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_QUERY_PROG_CNT_OFF,
            &prog_cnt)) {
        return 0;
    }

    requests[0].user_ptr = attr_ptr + BPF_DIRECT_PROG_QUERY_PROG_CNT_OFF;
    requests[0].user_len = sizeof(prog_cnt);
    requests[0].max_len = sizeof(prog_cnt);
    requests[0].storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    requests[0].arg_index = BPF_DIRECT_PROG_QUERY_PROG_CNT_OUT_ARG;

    u64 user_ptr = 0;
    if (bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_QUERY_PROG_IDS_OFF,
            &user_ptr)) {
        set_bpf_prog_query_array_request_direct(
            &requests[1],
            user_ptr,
            bpf_prog_query_array_len_direct(prog_cnt),
            BPF_DIRECT_PROG_QUERY_PROG_IDS_ARG);
    }
    if (bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_QUERY_PROG_ATTACH_FLAGS_OFF,
            &user_ptr)) {
        set_bpf_prog_query_array_request_direct(
            &requests[2],
            user_ptr,
            bpf_prog_query_array_len_direct(prog_cnt),
            BPF_DIRECT_PROG_QUERY_PROG_ATTACH_FLAGS_ARG);
    }
    if (bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_QUERY_LINK_IDS_OFF,
            &user_ptr)) {
        set_bpf_prog_query_array_request_direct(
            &requests[3],
            user_ptr,
            bpf_prog_query_array_len_direct(prog_cnt),
            BPF_DIRECT_PROG_QUERY_LINK_IDS_ARG);
    }
    if (bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_QUERY_LINK_ATTACH_FLAGS_OFF,
            &user_ptr)) {
        set_bpf_prog_query_array_request_direct(
            &requests[4],
            user_ptr,
            bpf_prog_query_array_len_direct(prog_cnt),
            BPF_DIRECT_PROG_QUERY_LINK_ATTACH_FLAGS_ARG);
    }
    return 1;
}

static __always_inline u32 capture_bpf_prog_query_outputs_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_exit_bytes_request requests[BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS],
    u16 *event_flags)
{
    u32 payload_size = 0;
#pragma unroll
    for (u32 i = 0; i < BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS; i++) {
        payload_size += capture_bpf_exit_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &requests[i],
            event_flags);
    }
    return payload_size;
}

static __always_inline int emit_bpf_prog_query_record_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    struct bpf_exit_bytes_request requests[BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS])
{
    u32 payload_capacity = BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS *
        (PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_PROG_QUERY_ARRAY_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    u16 flags = 0;
    u32 payload_size = capture_bpf_prog_query_outputs_direct(
        &ptr,
        payload_offset,
        requests,
        &flags);
    if (payload_size == 0) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 0;
    }
    flags |= EVENT_FLAG_PAYLOAD_TLV;

    struct event_v2_header header = {};
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
        &body,
        p,
        ret_value,
        duration,
        payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 1;
}

static __always_inline int emit_bpf_prog_query_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_PROG_QUERY ||
        ret_value != 0) {
        return 0;
    }

    struct bpf_exit_bytes_request requests[BPF_DIRECT_PROG_QUERY_OUTPUT_SECTIONS] = {};
    if (!read_bpf_prog_query_output_requests_direct(
            p->args[1],
            p->args[2],
            requests)) {
        return 0;
    }
    return emit_bpf_prog_query_record_v2_direct(
        p,
        ret_value,
        duration,
        requests);
}

#endif
