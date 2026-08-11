#ifndef STRACE_GO_SYSCALL_FD_ARRAY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_ARRAY_DIRECT_EVENT_V2_H

#define FD_ARRAY_DIRECT_SIZE 8
#define FD_ARRAY_DIRECT_FD_STATE_COUNT 2
#define FD_ARRAY_DIRECT_PAYLOAD_CAPACITY \
    (PAYLOAD_TLV_HEADER_SIZE + FD_ARRAY_DIRECT_SIZE + \
     FD_ARRAY_DIRECT_FD_STATE_COUNT * \
         (PAYLOAD_TLV_HEADER_SIZE + FD_STATE_SNAPSHOT_SIZE))

static __always_inline int is_fd_array_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PIPE || sys_id == SYS_PIPE2 || sys_id == SYS_SOCKETPAIR;
}

static __always_inline u16 fd_array_direct_arg_index(u32 sys_id)
{
    if (sys_id == SYS_SOCKETPAIR) {
        return 3;
    }
    return 0;
}

static __always_inline u64 fd_array_direct_user_ptr(struct pending_syscall *p)
{
    if (p->sys_id == SYS_SOCKETPAIR) {
        return p->args[3];
    }
    return p->args[0];
}

static __always_inline s32 read_fd_array_values_direct(
    struct pending_syscall *p,
    s32 fds[FD_ARRAY_DIRECT_FD_STATE_COUNT])
{
    u64 user_ptr = fd_array_direct_user_ptr(p);
    return (s32)bpf_probe_read_user(
        fds,
        FD_ARRAY_DIRECT_SIZE,
        (void *)user_ptr);
}

static __always_inline u32 capture_fd_array_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s32 fds[FD_ARRAY_DIRECT_FD_STATE_COUNT],
    s32 probe_ret)
{
    u16 arg_index = fd_array_direct_arg_index(p->sys_id);
    u64 user_ptr = fd_array_direct_user_ptr(p);

    u32 copied_len = probe_ret == 0 ? FD_ARRAY_DIRECT_SIZE : 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (probe_ret == 0) {
        long write_ret = bpf_dynptr_write(
            ptr,
            data_offset,
            fds,
            FD_ARRAY_DIRECT_SIZE,
            0);
        if (write_ret < 0) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            FD_ARRAY_DIRECT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_fd_state_array_tlvs_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    s32 fds[FD_ARRAY_DIRECT_FD_STATE_COUNT])
{
    u32 payload_size = 0;
#pragma unroll
    for (int i = 0; i < FD_ARRAY_DIRECT_FD_STATE_COUNT; i++) {
        u32 section_size = capture_fd_state_tlv_direct(
            ptr,
            payload_offset + payload_size,
            fds[i]);
        if (section_size == 0) {
            return payload_size;
        }
        payload_size += section_size;
    }
    return payload_size;
}

static __always_inline void emit_fd_array_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = FD_ARRAY_DIRECT_PAYLOAD_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = 0;
    if (ret_value == 0) {
        u64 user_ptr = fd_array_direct_user_ptr(p);
        if (user_ptr) {
            s32 fds[FD_ARRAY_DIRECT_FD_STATE_COUNT] = {};
            s32 probe_ret = read_fd_array_values_direct(p, fds);
            payload_size = capture_fd_array_tlv_direct(
                &ptr,
                payload_offset,
                p,
                fds,
                probe_ret);
            if (probe_ret == 0 && payload_size > 0) {
                payload_size += capture_fd_state_array_tlvs_direct(
                    &ptr,
                    payload_offset + payload_size,
                    fds);
            }
        }
    }
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
