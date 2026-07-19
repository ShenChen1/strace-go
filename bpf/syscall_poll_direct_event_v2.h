#ifndef STRACE_GO_SYSCALL_POLL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_POLL_DIRECT_EVENT_V2_H

#define POLL_DIRECT_FD_SIZE 8
#define POLL_DIRECT_FDS_MAX 512
#define POLL_DIRECT_FD_SLOT_MAX 64
#define POLL_DIRECT_TIMEOUT_SIZE 16
#define POLL_DIRECT_SIGMASK_SIZE 8

static __always_inline int is_poll_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_POLL || sys_id == SYS_PPOLL;
}

static __always_inline int is_ppoll_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PPOLL;
}

static __always_inline u64 poll_direct_count(u32 sys_id, u64 raw_count)
{
    if (is_ppoll_direct_syscall(sys_id)) {
        return (u32)raw_count;
    }
    return raw_count;
}

static __always_inline u32 poll_fds_user_len(u64 count)
{
    if (count > 0x1fffffffULL) {
        return 0xffffffffU;
    }
    return (u32)count * POLL_DIRECT_FD_SIZE;
}

static __always_inline u32 poll_fds_copy_len(u64 count)
{
    if (count > POLL_DIRECT_FD_SLOT_MAX) {
        return POLL_DIRECT_FDS_MAX;
    }
    return (u32)count * POLL_DIRECT_FD_SIZE;
}

static __always_inline u32 capture_poll_fds_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 count,
    u16 tlv_flags,
    u16 *event_flags)
{
    u32 user_len = poll_fds_user_len(count);
    u32 target_len = poll_fds_copy_len(count);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < POLL_DIRECT_FD_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * POLL_DIRECT_FD_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 fd_data[POLL_DIRECT_FD_SIZE] = {};
        long err = bpf_probe_read_user(&fd_data, POLL_DIRECT_FD_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &fd_data, POLL_DIRECT_FD_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += POLL_DIRECT_FD_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            0,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_poll_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = POLL_DIRECT_TIMEOUT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, POLL_DIRECT_TIMEOUT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, POLL_DIRECT_TIMEOUT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            2,
            tlv_flags,
            POLL_DIRECT_TIMEOUT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_poll_sigmask_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 sigset_size)
{
    if (!user_ptr || sigset_size == 0) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = POLL_DIRECT_SIGMASK_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, POLL_DIRECT_SIGMASK_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, POLL_DIRECT_SIGMASK_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            0,
            payload_tlv_clamp_u32(sigset_size),
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_poll_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_FDS_MAX;
    if (is_ppoll_direct_syscall(sys_id)) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_TIMEOUT_SIZE;
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_SIGMASK_SIZE;
    }
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
    u32 payload_size = capture_poll_fds_tlv_direct(
        &ptr,
        payload_offset,
        ctx->args[0],
        poll_direct_count(sys_id, ctx->args[1]),
        0,
        &flags);
    if (is_ppoll_direct_syscall(sys_id)) {
        payload_size += capture_poll_timeout_tlv_direct(&ptr, payload_offset + payload_size, ctx->args[2], 0);
        payload_size += capture_poll_sigmask_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            ctx->args[3],
            ctx->args[4]);
    }
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_poll_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_FDS_MAX;
    if (is_ppoll_direct_syscall(p->sys_id)) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + POLL_DIRECT_TIMEOUT_SIZE;
    }
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
    u32 payload_size = capture_poll_fds_tlv_direct(
        &ptr,
        payload_offset,
        p->args[0],
        poll_direct_count(p->sys_id, p->args[1]),
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        &flags);
    if (is_ppoll_direct_syscall(p->sys_id)) {
        payload_size += capture_poll_timeout_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            p->args[2],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
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
