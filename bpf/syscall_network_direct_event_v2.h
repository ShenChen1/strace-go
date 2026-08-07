#ifndef STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H

#define NETWORK_DIRECT_BYTES_MAX 512
#define NETWORK_DIRECT_SOCKADDR_MAX 128
#define NETWORK_DIRECT_SOCKLEN_SIZE 4
#define NETWORK_DIRECT_SENDTO_ENTER_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_BYTES_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKADDR_MAX)
#define NETWORK_DIRECT_RECVFROM_EXIT_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_BYTES_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKADDR_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKLEN_SIZE)

struct network_direct_args {
    u64 args[6];
};

static __always_inline int is_network_accept_like_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ACCEPT || sys_id == SYS_ACCEPT4 ||
        sys_id == SYS_GETSOCKNAME || sys_id == SYS_GETPEERNAME;
}

static __always_inline int is_network_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CONNECT || sys_id == SYS_BIND ||
        sys_id == SYS_SENDTO || sys_id == SYS_RECVFROM ||
        is_network_accept_like_direct_syscall(sys_id);
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
    if (arg_index == 4) {
        return p->args[4];
    }
    if (arg_index == 5) {
        return p->args[5];
    }
    return 0;
}

static __always_inline u32 network_direct_min_u32(u32 a, u32 b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static __always_inline int network_direct_read_socklen(u64 user_ptr, u32 *value)
{
    *value = 0;
    if (!user_ptr) {
        return -1;
    }
    long err = bpf_probe_read_user(value, NETWORK_DIRECT_SOCKLEN_SIZE, (void *)user_ptr);
    if (err < 0) {
        return err;
    }
    return 0;
}

static __always_inline void *network_direct_payload_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 max)
{
    if (max == NETWORK_DIRECT_BYTES_MAX) {
        return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_BYTES_MAX);
    }
    if (max == NETWORK_DIRECT_SOCKADDR_MAX) {
        return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_SOCKADDR_MAX);
    }
    return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_SOCKLEN_SIZE);
}

static __always_inline u32 capture_network_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 kind,
    u16 arg_index,
    u16 tlv_flags,
    u64 user_ptr,
    u32 user_len,
    u32 copy_len,
    u32 storage_max,
    u16 *event_flags)
{
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    u32 copied_len = network_direct_min_u32(copy_len, storage_max);
    copied_len = network_direct_min_u32(copied_len, user_len);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = network_direct_payload_data(ptr, data_offset, storage_max);
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
            kind,
            arg_index,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_network_socklen_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u16 tlv_flags,
    u64 user_ptr,
    u32 *value)
{
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = network_direct_read_socklen(user_ptr, value);
    u32 copied_len = probe_ret == 0 ? NETWORK_DIRECT_SOCKLEN_SIZE : 0;
    if (copied_len > 0) {
        long ret = bpf_dynptr_write(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            value,
            NETWORK_DIRECT_SOCKLEN_SIZE,
            0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            probe_ret = ret;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            arg_index,
            tlv_flags,
            NETWORK_DIRECT_SOCKLEN_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
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
    if (sys_id == SYS_CONNECT || sys_id == SYS_BIND) {
        return capture_network_tlv_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_STRUCT, 1, 0,
            args->args[1], payload_tlv_clamp_u32(args->args[2]),
            payload_tlv_clamp_u32(args->args[2]),
            NETWORK_DIRECT_SOCKADDR_MAX, event_flags);
    }
    if (sys_id == SYS_SENDTO) {
        u32 payload_size = capture_network_tlv_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_BYTES, 1, 0,
            args->args[1], payload_tlv_clamp_u32(args->args[2]),
            payload_tlv_clamp_u32(args->args[2]),
            NETWORK_DIRECT_BYTES_MAX, event_flags);
        payload_size += capture_network_tlv_direct(
            ptr, payload_offset + payload_size, PAYLOAD_TLV_KIND_STRUCT, 4, 0,
            args->args[4], payload_tlv_clamp_u32(args->args[5]),
            payload_tlv_clamp_u32(args->args[5]),
            NETWORK_DIRECT_SOCKADDR_MAX, event_flags);
        return payload_size;
    }

    u32 len_arg = network_direct_enter_socklen_arg(sys_id);
    if (len_arg < 6) {
        return capture_network_socklen_tlv_direct(
            ptr, payload_offset, len_arg, 0,
            network_direct_arg(args, len_arg), sockaddr_len);
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

static __always_inline u32 capture_network_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (p->sys_id == SYS_RECVFROM && ret_value > 0) {
        u32 ret_len = payload_tlv_clamp_u32((u64)ret_value);
        u32 count_len = payload_tlv_clamp_u32(p->args[2]);
        u32 copy_len = ret_len;
        if (count_len < copy_len) {
            copy_len = count_len;
        }
        payload_size += capture_network_tlv_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_BYTES, 1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT, p->args[1],
            ret_len, copy_len, NETWORK_DIRECT_BYTES_MAX,
            event_flags);
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
        payload_size += capture_network_tlv_direct(
            ptr,
            payload_offset + payload_size,
            PAYLOAD_TLV_KIND_STRUCT,
            addr_arg,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            addr_ptr,
            copy_len,
            copy_len,
            NETWORK_DIRECT_SOCKADDR_MAX,
            event_flags);
    }
    payload_size += capture_network_socklen_tlv_direct(
        ptr,
        payload_offset + payload_size,
        len_arg,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        len_ptr,
        &out_len);
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
