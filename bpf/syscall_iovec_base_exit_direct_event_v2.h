#ifndef STRACE_GO_SYSCALL_IOVEC_BASE_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_IOVEC_BASE_EXIT_DIRECT_EVENT_V2_H

#define IOVEC_BASE_EXIT_PAYLOAD_SLOT_MAX 5
#define IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX 8
#define IOVEC_BASE_EXIT_PAYLOAD_CAPACITY \
    (IOVEC_BASE_EXIT_PAYLOAD_SLOT_MAX * (PAYLOAD_TLV_HEADER_SIZE + IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX))

static __always_inline u32 iovec_base_exit_payload_copy_len(u64 len)
{
    if (len > IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX) {
        return IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX;
    }
    return (u32)len;
}

static __always_inline u32 capture_iovec_base_exit_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 payload_arg_index,
    u64 user_ptr,
    u64 user_len,
    u16 *event_flags)
{
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = iovec_base_exit_payload_copy_len(user_len);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, IOVEC_BASE_EXIT_PAYLOAD_BYTES_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            payload_arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            (u32)user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_iovec_base_exit_payloads_tlv_direct_for_arg(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 iovec_arg_index,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    if (!iovec_ptr || count == 0) {
        return 0;
    }

    u32 payload_size = 0;

    u64 slot0 = iovec_ptr;
    u64 base0 = 0;
    u64 len0 = 0;
    if (bpf_probe_read_user(&base0, sizeof(base0), (void *)slot0) < 0) {
        return 0;
    }
    if (bpf_probe_read_user(&len0, sizeof(len0), (void *)(slot0 + 8)) < 0) {
        return 0;
    }
    payload_size += capture_iovec_base_exit_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iovec_base_payload_arg_index(iovec_arg_index, 0),
        base0,
        len0,
        event_flags);

    if (count <= 1) {
        return payload_size;
    }

    u64 slot1 = iovec_ptr + IOVEC_DIRECT_ELEM_SIZE;
    u64 base1 = 0;
    u64 len1 = 0;
    if (bpf_probe_read_user(&base1, sizeof(base1), (void *)slot1) < 0) {
        return payload_size;
    }
    if (bpf_probe_read_user(&len1, sizeof(len1), (void *)(slot1 + 8)) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iovec_base_payload_arg_index(iovec_arg_index, 1),
        base1,
        len1,
        event_flags);

    if (count <= 2) {
        return payload_size;
    }

    u64 slot2 = iovec_ptr + (2 * IOVEC_DIRECT_ELEM_SIZE);
    u64 base2 = 0;
    u64 len2 = 0;
    if (bpf_probe_read_user(&base2, sizeof(base2), (void *)slot2) < 0) {
        return payload_size;
    }
    if (bpf_probe_read_user(&len2, sizeof(len2), (void *)(slot2 + 8)) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iovec_base_payload_arg_index(iovec_arg_index, 2),
        base2,
        len2,
        event_flags);

    if (count <= 3) {
        return payload_size;
    }

    u64 slot3 = iovec_ptr + (3 * IOVEC_DIRECT_ELEM_SIZE);
    u64 base3 = 0;
    u64 len3 = 0;
    if (bpf_probe_read_user(&base3, sizeof(base3), (void *)slot3) < 0) {
        return payload_size;
    }
    if (bpf_probe_read_user(&len3, sizeof(len3), (void *)(slot3 + 8)) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iovec_base_payload_arg_index(iovec_arg_index, 3),
        base3,
        len3,
        event_flags);

    if (count <= 4) {
        return payload_size;
    }

    u64 slot4 = iovec_ptr + (4 * IOVEC_DIRECT_ELEM_SIZE);
    u64 base4 = 0;
    u64 len4 = 0;
    if (bpf_probe_read_user(&base4, sizeof(base4), (void *)slot4) < 0) {
        return payload_size;
    }
    if (bpf_probe_read_user(&len4, sizeof(len4), (void *)(slot4 + 8)) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iovec_base_payload_arg_index(iovec_arg_index, 4),
        base4,
        len4,
        event_flags);

    return payload_size;
}

static __noinline u32 capture_iovec_base_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    return capture_iovec_base_exit_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        1,
        iovec_ptr,
        count,
        event_flags);
}

static __noinline u32 capture_iovec_base_exit_payloads_arg151_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    return capture_iovec_base_exit_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        151,
        iovec_ptr,
        count,
        event_flags);
}

static __noinline void emit_iovec_base_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = IOVEC_BASE_EXIT_PAYLOAD_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_iovec_base_exit_payloads_tlv_direct(
        &ptr,
        payload_offset,
        p->args[1],
        p->args[2],
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, bpf_ktime_get_ns());
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
