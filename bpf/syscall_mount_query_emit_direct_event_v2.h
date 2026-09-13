#ifndef STRACE_GO_SYSCALL_MOUNT_QUERY_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MOUNT_QUERY_EMIT_DIRECT_EVENT_V2_H

static __always_inline void emit_mount_query_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = p->sys_id == SYS_STATMOUNT
        ? STATMOUNT_EXIT_PAYLOAD_CAPACITY : LISTMOUNT_EXIT_PAYLOAD_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = body_offset + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long reserve_ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (reserve_ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = p->sys_id == SYS_STATMOUNT
        ? capture_statmount_exit_tlv_direct(&ptr, payload_offset, p, &flags)
        : capture_listmount_ids_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
    init_syscall_event_v2_header_direct(
        &header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id,
        out_size, p->enter_time + duration);
    if (bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0) < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body, p, ret_value, duration, payload_size);
    if (bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0) < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
