#ifndef STRACE_GO_SYSCALL_NETWORK_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_EMIT_DIRECT_EVENT_V2_H

static __always_inline void init_network_enter_event_v2_from_args(
    struct syscall_enter_event_v2 *body,
    struct network_direct_args *args,
    u32 payload_size)
{
    body->ret = 0;
    body->probe_ret_enter = -1;
    body->probe_ret_exit = -1;
    body->args[0] = args->args[0];
    body->args[1] = args->args[1];
    body->args[2] = args->args[2];
    body->args[3] = args->args[3];
    body->args[4] = args->args[4];
    body->args[5] = args->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void emit_network_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct network_direct_args *args,
    u64 ts_ns,
    u32 *sockaddr_len)
{
    u32 payload_capacity = NETWORK_DIRECT_SENDTO_ENTER_MAX;
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
    u32 payload_size = capture_network_enter_payloads_tlv_direct(
        &ptr, payload_offset, sys_id, args, &flags, sockaddr_len);
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

    struct syscall_enter_event_v2 body = {};
    init_network_enter_event_v2_from_args(&body, args, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
