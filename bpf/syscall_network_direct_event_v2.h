#ifndef STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H

#include "syscall_network_capture_direct_event_v2.h"

struct network_direct_args {
    u64 args[6];
};

static __always_inline int is_network_accept_like_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ACCEPT || sys_id == SYS_ACCEPT4 ||
        sys_id == SYS_GETSOCKNAME || sys_id == SYS_GETPEERNAME;
}

static __always_inline int is_network_sockopt_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETSOCKOPT || sys_id == SYS_GETSOCKOPT;
}

static __always_inline int is_network_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CONNECT || sys_id == SYS_BIND ||
        sys_id == SYS_SENDTO || sys_id == SYS_RECVFROM ||
        is_network_accept_like_direct_syscall(sys_id) ||
        is_network_sockopt_direct_syscall(sys_id);
}

static __always_inline u32 network_direct_enter_socklen_arg(u32 sys_id)
{
    if (sys_id == SYS_RECVFROM) {
        return 5;
    }
    if (is_network_accept_like_direct_syscall(sys_id)) {
        return 2;
    }
    return 6;
}

static __always_inline u64 network_direct_arg(
    struct network_direct_args *args,
    u32 arg_index)
{
    if (arg_index == 0) {
        return args->args[0];
    }
    if (arg_index == 1) {
        return args->args[1];
    }
    if (arg_index == 2) {
        return args->args[2];
    }
    if (arg_index == 3) {
        return args->args[3];
    }
    if (arg_index == 4) {
        return args->args[4];
    }
    if (arg_index == 5) {
        return args->args[5];
    }
    return 0;
}

static __always_inline u64 network_direct_pending_arg(
    struct pending_syscall *p,
    u32 arg_index)
{
    if (arg_index == 1) {
        return p->args[1];
    }
    if (arg_index == 2) {
        return p->args[2];
    }
    if (arg_index == 3) {
        return p->args[3];
    }
    if (arg_index == 4) {
        return p->args[4];
    }
    if (arg_index == 5) {
        return p->args[5];
    }
    return 0;
}

static __always_inline void save_pending_network_syscall_args(
    u32 tid,
    u32 pid,
    u32 sys_id,
    struct network_direct_args *args,
    u64 enter_time,
    s32 stack_id,
    u32 sockaddr_len)
{
    struct pending_syscall p = {};

    p.enter_time = enter_time;
    p.args[0] = args->args[0];
    p.args[1] = args->args[1];
    p.args[2] = args->args[2];
    p.args[3] = args->args[3];
    p.args[4] = args->args[4];
    p.args[5] = args->args[5];
    p.pid = pid;
    p.sys_id = sys_id;
    p.tid = tid;
    p.stack_id = stack_id;
    p.aux0 = sockaddr_len;

    if (bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY) != 0) {
        record_pending_update_fail();
    }
}

static __always_inline u32 capture_network_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct network_direct_args *args,
    u16 *event_flags,
    u32 *sockaddr_len)
{
    *sockaddr_len = 0;
    if (sys_id == SYS_SETSOCKOPT) {
        u32 optlen = network_direct_sockopt_payload_len(
            args->args[1], args->args[2], args->args[4]);
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.kind = PAYLOAD_TLV_KIND_BYTES;
        request.arg_index = 3;
        request.user_ptr = args->args[3];
        request.user_len = optlen;
        request.copy_len = optlen;
        request.storage_max = NETWORK_DIRECT_SOCKOPT_MAX;
        request.event_flags = event_flags;
        return capture_network_tlv_direct(&request);
    }
    if (sys_id == SYS_GETSOCKOPT) {
        u32 optlen = 0;
        struct network_socklen_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.arg_index = 4;
        request.user_ptr = args->args[4];
        request.value = &optlen;
        u32 payload_size = capture_network_socklen_tlv_direct(&request);
        *sockaddr_len = optlen;
        return payload_size;
    }
    if (sys_id == SYS_CONNECT || sys_id == SYS_BIND) {
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.kind = PAYLOAD_TLV_KIND_STRUCT;
        request.arg_index = 1;
        request.user_ptr = args->args[1];
        request.user_len = payload_tlv_clamp_u32(args->args[2]);
        request.copy_len = request.user_len;
        request.storage_max = NETWORK_DIRECT_SOCKADDR_MAX;
        request.event_flags = event_flags;
        return capture_network_tlv_direct(&request);
    }
    if (sys_id == SYS_SENDTO) {
        struct network_tlv_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.kind = PAYLOAD_TLV_KIND_BYTES;
        request.arg_index = 1;
        request.user_ptr = args->args[1];
        request.user_len = payload_tlv_clamp_u32(args->args[2]);
        request.copy_len = request.user_len;
        request.storage_max = NETWORK_DIRECT_BYTES_MAX;
        request.event_flags = event_flags;
        u32 payload_size = capture_network_tlv_direct(&request);
        request.payload_offset = payload_offset + payload_size;
        request.kind = PAYLOAD_TLV_KIND_STRUCT;
        request.arg_index = 4;
        request.user_ptr = args->args[4];
        request.user_len = payload_tlv_clamp_u32(args->args[5]);
        request.copy_len = request.user_len;
        request.storage_max = NETWORK_DIRECT_SOCKADDR_MAX;
        payload_size += capture_network_tlv_direct(&request);
        return payload_size;
    }

    u32 len_arg = network_direct_enter_socklen_arg(sys_id);
    if (len_arg < 6) {
        struct network_socklen_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.arg_index = len_arg;
        request.user_ptr = network_direct_arg(args, len_arg);
        request.value = sockaddr_len;
        return capture_network_socklen_tlv_direct(&request);
    }
    return 0;
}

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

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
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
