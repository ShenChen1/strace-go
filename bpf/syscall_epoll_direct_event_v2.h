#ifndef STRACE_GO_SYSCALL_EPOLL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_EPOLL_DIRECT_EVENT_V2_H

#define EPOLL_DIRECT_EVENT_SIZE 12
#define EPOLL_DIRECT_TIMEOUT_SIZE 16
#define EPOLL_DIRECT_EVENTS_MAX 504
#define EPOLL_DIRECT_EVENT_SLOT_MAX 42

static __always_inline int is_epoll_pwait2_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_PWAIT2;
}

static __always_inline int is_epoll_ctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_CTL;
}

static __always_inline int is_epoll_wait_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_WAIT || sys_id == SYS_EPOLL_PWAIT ||
        is_epoll_pwait2_direct_syscall(sys_id);
}

static __always_inline int is_epoll_direct_syscall(u32 sys_id)
{
    return is_epoll_ctl_direct_syscall(sys_id) ||
        is_epoll_wait_direct_syscall(sys_id);
}

static __always_inline u32 epoll_events_user_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > 0x15555555LL) {
        return 0xffffffffU;
    }
    return (u32)count * EPOLL_DIRECT_EVENT_SIZE;
}

static __always_inline u32 epoll_events_copy_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > EPOLL_DIRECT_EVENT_SLOT_MAX) {
        return EPOLL_DIRECT_EVENTS_MAX;
    }
    return (u32)count * EPOLL_DIRECT_EVENT_SIZE;
}

static __always_inline u32 capture_epoll_events_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u64 user_ptr = p->args[1];
    u32 user_len = epoll_events_user_len(ret_value);
    u32 target_len = epoll_events_copy_len(ret_value);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < EPOLL_DIRECT_EVENT_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * EPOLL_DIRECT_EVENT_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 event_data[EPOLL_DIRECT_EVENT_SIZE] = {};
        long err = bpf_probe_read_user(&event_data, EPOLL_DIRECT_EVENT_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &event_data, EPOLL_DIRECT_EVENT_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += EPOLL_DIRECT_EVENT_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_epoll_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6])
{
    u64 user_ptr = args[3];
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = EPOLL_DIRECT_TIMEOUT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, EPOLL_DIRECT_TIMEOUT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, EPOLL_DIRECT_TIMEOUT_SIZE, (void *)user_ptr);
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
            EPOLL_DIRECT_TIMEOUT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_epoll_ctl_event_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6])
{
    u64 user_ptr = args[3];
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = EPOLL_DIRECT_EVENT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, EPOLL_DIRECT_EVENT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, EPOLL_DIRECT_EVENT_SIZE, (void *)user_ptr);
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
            EPOLL_DIRECT_EVENT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_epoll_ctl_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return;
    }
    copy_syscall_enter_args(scratch->args, ctx);
    u32 fd_path_capacity = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        fd_path_capacity = fd_path_payload_capacity(sys_id);
    }
    u32 payload_capacity = fd_path_capacity + PAYLOAD_TLV_HEADER_SIZE + EPOLL_DIRECT_EVENT_SIZE;
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
    u32 payload_size = 0;
    if (fd_path_capacity > 0) {
        payload_size = capture_fd_paths_tlv_direct(&ptr, payload_offset, sys_id, scratch->args);
    }
    payload_size += capture_epoll_ctl_event_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        scratch->args);
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
    init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_epoll_pwait2_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return;
    }
    copy_syscall_enter_args(scratch->args, ctx);
    u32 fd_path_capacity = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        fd_path_capacity = fd_path_payload_capacity(sys_id);
    }
    u32 payload_capacity = fd_path_capacity + PAYLOAD_TLV_HEADER_SIZE + EPOLL_DIRECT_TIMEOUT_SIZE;
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
    u32 payload_size = 0;
    if (fd_path_capacity > 0) {
        payload_size = capture_fd_paths_tlv_direct(&ptr, payload_offset, sys_id, scratch->args);
    }
    payload_size += capture_epoll_timeout_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        scratch->args);
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
    init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_epoll_wait_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + EPOLL_DIRECT_EVENTS_MAX;
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
    u32 payload_size = capture_epoll_events_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
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
