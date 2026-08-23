#ifndef STRACE_GO_SYSCALL_BPF_TASK_FD_QUERY_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_TASK_FD_QUERY_EXIT_DIRECT_EVENT_V2_H

#define BPF_DIRECT_TASK_FD_QUERY 20
#define BPF_DIRECT_TASK_FD_QUERY_BUF_OUT_ARG 137
#define BPF_DIRECT_TASK_FD_QUERY_ATTR_OUT_ARG 138
#define BPF_DIRECT_TASK_FD_QUERY_ATTR_MAX 64
#define BPF_DIRECT_TASK_FD_QUERY_BUF_LEN_OFF 12
#define BPF_DIRECT_TASK_FD_QUERY_BUF_OFF 16
#define BPF_DIRECT_TASK_FD_QUERY_BUF_MAX 512

struct bpf_task_fd_query_string_request {
    u64 user_ptr;
    u32 user_len;
    u16 arg_index;
    u16 *event_flags;
};

static __always_inline int read_bpf_task_fd_query_output_attr_direct(
    struct pending_syscall *p,
    struct bpf_exit_bytes_request *request)
{
    u32 attr_len = p->args[2];
    if (!p->args[1] || attr_len == 0) {
        return 0;
    }
    if (attr_len > BPF_DIRECT_TASK_FD_QUERY_ATTR_MAX) {
        attr_len = BPF_DIRECT_TASK_FD_QUERY_ATTR_MAX;
    }
    request->user_ptr = p->args[1];
    request->user_len = attr_len;
    request->max_len = BPF_DIRECT_TASK_FD_QUERY_ATTR_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = BPF_DIRECT_TASK_FD_QUERY_ATTR_OUT_ARG;
    return 1;
}

static __always_inline int read_bpf_task_fd_query_string_request_direct(
    struct pending_syscall *p,
    struct bpf_task_fd_query_string_request *request)
{
    u64 exit_buf = 0;
    u32 exit_buf_len = 0;
    u32 enter_buf_len = lookup_pending_syscall_aux0(p->tid);
    if (!enter_buf_len ||
        !bpf_attr_read_u64_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_TASK_FD_QUERY_BUF_OFF,
            &exit_buf) ||
        !bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_TASK_FD_QUERY_BUF_LEN_OFF,
            &exit_buf_len) ||
        !exit_buf) {
        return 0;
    }

    u32 bounded_len = enter_buf_len;
    if (exit_buf_len < bounded_len) {
        bounded_len = exit_buf_len;
    }
    if (bounded_len > BPF_DIRECT_TASK_FD_QUERY_BUF_MAX) {
        bounded_len = BPF_DIRECT_TASK_FD_QUERY_BUF_MAX;
    }
    if (bounded_len == 0) {
        return 0;
    }

    request->user_ptr = exit_buf;
    request->user_len = bounded_len;
    request->arg_index = BPF_DIRECT_TASK_FD_QUERY_BUF_OUT_ARG;
    return 1;
}

static __always_inline u32 capture_bpf_task_fd_query_string_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_task_fd_query_string_request *request,
    u16 *event_flags)
{
    if (!request->user_ptr || request->user_len == 0) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        data_offset,
        BPF_DIRECT_TASK_FD_QUERY_BUF_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(
            payload_data,
            BPF_DIRECT_TASK_FD_QUERY_BUF_MAX,
            (void *)request->user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > BPF_DIRECT_TASK_FD_QUERY_BUF_MAX) {
            copied_len = BPF_DIRECT_TASK_FD_QUERY_BUF_MAX;
        } else {
            copied_len = (u32)n;
        }
    }

    if (probe_ret == 0 && copied_len == BPF_DIRECT_TASK_FD_QUERY_BUF_MAX &&
        request->user_len > copied_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            request->arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            request->user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline int emit_bpf_task_fd_query_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_TASK_FD_QUERY || ret_value != 0) {
        return 0;
    }

    struct bpf_exit_bytes_request attr_request = {};
    struct bpf_task_fd_query_string_request string_request = {};
    int have_attr = read_bpf_task_fd_query_output_attr_direct(p, &attr_request);
    int have_string = read_bpf_task_fd_query_string_request_direct(
        p,
        &string_request);
    if (!have_attr && !have_string) {
        return 0;
    }

    u32 payload_capacity = 2 * (PAYLOAD_TLV_HEADER_SIZE +
        BPF_DIRECT_TASK_FD_QUERY_BUF_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long reserve_ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (reserve_ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    u16 flags = 0;
    u32 payload_size = 0;
    if (have_attr) {
        payload_size += capture_bpf_exit_bytes_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            &attr_request,
            &flags);
    }
    if (have_string) {
        payload_size += capture_bpf_task_fd_query_string_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            &string_request,
            &flags);
    }
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
    reserve_ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (reserve_ret < 0) {
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
    reserve_ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (reserve_ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 1;
}

#endif
