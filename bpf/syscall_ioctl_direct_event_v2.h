#ifndef STRACE_GO_SYSCALL_IOCTL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_IOCTL_DIRECT_EVENT_V2_H

#define IOCTL_DIRECT_BYTES_MAX 512
#define IOCTL_DIRECT_ZERO_SIZE_LEN 128
#define IOCTL_DIRECT_SIZE_SHIFT 16
#define IOCTL_DIRECT_SIZE_MASK 0x3fff

static __always_inline u32 ioctl_direct_known_size(u64 cmd)
{
    switch ((u32)cmd) {
    case 0x541b: /* FIONREAD */
        return 4;
    case 0x5413: /* TIOCGWINSZ */
        return 8;
    case 0x5401: /* TCGETS */
    case 0x5402: /* TCSETS */
    case 0x5403: /* TCSETSW */
    case 0x5404: /* TCSETSF */
        return 60;
    default:
        return 0;
    }
}

static __always_inline int is_ioctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IOCTL;
}

static __always_inline u32 ioctl_direct_user_len(u64 cmd)
{
    u32 known_size = ioctl_direct_known_size(cmd);
    if (known_size > 0) {
        return known_size;
    }
    u32 size = (u32)((cmd >> IOCTL_DIRECT_SIZE_SHIFT) & IOCTL_DIRECT_SIZE_MASK);
    if (size == 0) {
        return IOCTL_DIRECT_ZERO_SIZE_LEN;
    }
    return size;
}

static __always_inline u32 capture_ioctl_arg_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 cmd,
    u64 user_ptr,
    u16 tlv_flags,
    u16 *event_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 user_len = ioctl_direct_user_len(cmd);
    u32 copied_len = payload_tlv_copy_len(user_len, IOCTL_DIRECT_BYTES_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, IOCTL_DIRECT_BYTES_MAX);
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
            2,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_ioctl_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + IOCTL_DIRECT_BYTES_MAX;
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
    u32 payload_size = capture_ioctl_arg_tlv_direct(
        &ptr,
        payload_offset,
        ctx->args[1],
        ctx->args[2],
        0,
        &flags);
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

static __always_inline void emit_ioctl_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + IOCTL_DIRECT_BYTES_MAX;
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
    if (ret_value >= 0) {
        payload_size = capture_ioctl_arg_tlv_direct(
            &ptr,
            payload_offset,
            p->args[1],
            p->args[2],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            &flags);
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
