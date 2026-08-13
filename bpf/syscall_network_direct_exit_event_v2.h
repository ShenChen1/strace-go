#ifndef STRACE_GO_SYSCALL_NETWORK_DIRECT_EXIT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_DIRECT_EXIT_EVENT_V2_H

/* Exit-side network payloads are kept separate so the family header stays small. */

static __always_inline u32 network_direct_out_sockaddr_arg(u32 sys_id)
{
    if (sys_id == SYS_RECVFROM) {
        return 4;
    }
    return 1;
}

static __always_inline u32 network_direct_out_socklen_arg(u32 sys_id)
{
    if (sys_id == SYS_RECVFROM) {
        return 5;
    }
    return 2;
}

static __always_inline u32 capture_network_getsockopt_exit_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u32 payload_size = 0;
    u32 out_len = 0;
    u64 len_ptr = network_direct_pending_arg(p, 4);
    long read_ret = network_direct_read_socklen(len_ptr, &out_len);
    if (ret_value >= 0 && read_ret == 0 && out_len > 0 && p->aux0 > 0) {
        u32 user_len = network_direct_min_u32(out_len, p->aux0);
        u32 copy_len = network_direct_sockopt_payload_len(
            p->args[1], p->args[2], user_len);
        copy_len = network_direct_min_u32(copy_len, NETWORK_DIRECT_SOCKOPT_MAX);
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.kind = PAYLOAD_TLV_KIND_BYTES;
        request.arg_index = 3;
        request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
        request.user_ptr = network_direct_pending_arg(p, 3);
        request.user_len = user_len;
        request.copy_len = copy_len;
        request.storage_max = NETWORK_DIRECT_SOCKOPT_MAX;
        request.event_flags = event_flags;
        payload_size = capture_network_tlv_direct(&request);
    }
    struct network_socklen_capture_request len_request = {};
    len_request.ptr = ptr;
    len_request.payload_offset = payload_offset + payload_size;
    len_request.arg_index = 4;
    len_request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
    len_request.user_ptr = len_ptr;
    len_request.value = &out_len;
    payload_size += capture_network_socklen_tlv_direct(&len_request);
    return payload_size;
}

static __always_inline u32 capture_network_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (is_network_sockopt_direct_syscall(p->sys_id)) {
        if (p->sys_id == SYS_GETSOCKOPT) {
            payload_size = capture_network_getsockopt_exit_tlv_direct(
                ptr, payload_offset, p, ret_value, event_flags);
        }
        return payload_size;
    }
    if (p->sys_id == SYS_RECVFROM && ret_value > 0) {
        u32 ret_len = payload_tlv_clamp_u32((u64)ret_value);
        u32 count_len = payload_tlv_clamp_u32(p->args[2]);
        u32 copy_len = ret_len;
        if (count_len < copy_len) {
            copy_len = count_len;
        }
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.kind = PAYLOAD_TLV_KIND_BYTES;
        request.arg_index = 1;
        request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
        request.user_ptr = p->args[1];
        request.user_len = ret_len;
        request.copy_len = copy_len;
        request.storage_max = NETWORK_DIRECT_BYTES_MAX;
        request.event_flags = event_flags;
        payload_size += capture_network_tlv_direct(&request);
    }
    if (ret_value < 0) {
        return payload_size;
    }
    if (p->sys_id != SYS_RECVFROM && !is_network_accept_like_direct_syscall(p->sys_id)) {
        return payload_size;
    }

    u32 len_arg = network_direct_out_socklen_arg(p->sys_id);
    u32 out_len = 0;
    u64 len_ptr = network_direct_pending_arg(p, len_arg);
    network_direct_read_socklen(len_ptr, &out_len);

    u32 copy_len = out_len;
    if (p->aux0 > 0 && p->aux0 < copy_len) {
        copy_len = p->aux0;
    }
    copy_len = network_direct_min_u32(copy_len, NETWORK_DIRECT_SOCKADDR_MAX);
    if (copy_len > 0) {
        u32 addr_arg = network_direct_out_sockaddr_arg(p->sys_id);
        u64 addr_ptr = network_direct_pending_arg(p, addr_arg);
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset + payload_size;
        request.kind = PAYLOAD_TLV_KIND_STRUCT;
        request.arg_index = addr_arg;
        request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
        request.user_ptr = addr_ptr;
        request.user_len = copy_len;
        request.copy_len = copy_len;
        request.storage_max = NETWORK_DIRECT_SOCKADDR_MAX;
        request.event_flags = event_flags;
        payload_size += capture_network_tlv_direct(&request);
    }
    struct network_socklen_capture_request len_request = {};
    len_request.ptr = ptr;
    len_request.payload_offset = payload_offset + payload_size;
    len_request.arg_index = len_arg;
    len_request.tlv_flags = PAYLOAD_TLV_FLAG_DIRECTION_OUT;
    len_request.user_ptr = len_ptr;
    len_request.value = &out_len;
    payload_size += capture_network_socklen_tlv_direct(&len_request);
    return payload_size;
}

static __always_inline void emit_network_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + NETWORK_DIRECT_RECVFROM_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_network_exit_payloads_tlv_direct(
        &ptr, payload_offset, p, ret_value, &flags);
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
