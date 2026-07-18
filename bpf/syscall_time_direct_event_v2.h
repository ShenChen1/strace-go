#ifndef STRACE_GO_SYSCALL_TIME_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_TIME_DIRECT_EVENT_V2_H

#define TIME_DIRECT_TIMESPEC_SIZE 16
#define TIME_DIRECT_TIMEZONE_SIZE 8

static __always_inline int is_clock_time_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CLOCK_GETTIME || sys_id == SYS_CLOCK_GETRES;
}

static __always_inline int is_gettimeofday_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETTIMEOFDAY;
}

static __always_inline int is_time_struct_direct_syscall(u32 sys_id)
{
    return is_clock_time_struct_direct_syscall(sys_id) || is_gettimeofday_direct_syscall(sys_id);
}

static __always_inline int is_sys_exit_direct_syscall(u32 sys_id)
{
    return is_direct_syscall(sys_id) ||
        is_getcwd_direct_syscall(sys_id) ||
        is_time_struct_direct_syscall(sys_id) ||
        is_stat_struct_direct_syscall(sys_id) ||
        is_readlink_direct_syscall(sys_id) ||
        is_fd_array_direct_syscall(sys_id) ||
        is_misc_struct_direct_syscall(sys_id) ||
        is_small_struct_direct_syscall(sys_id);
}

static __always_inline u32 capture_time_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 arg_index,
    u32 struct_size)
{
    if (arg_index >= 6 || struct_size == 0) {
        return 0;
    }

    u64 user_ptr = p->args[arg_index];
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (struct_size == TIME_DIRECT_TIMEZONE_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMEZONE_SIZE);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMESPEC_SIZE);
    }
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, struct_size, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_time_struct_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE;
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
        payload_size = capture_time_struct_tlv_direct(
            &ptr,
            payload_offset,
            p,
            1,
            TIME_DIRECT_TIMESPEC_SIZE);
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

static __always_inline void emit_gettimeofday_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE +
        PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMEZONE_SIZE;
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
        payload_size = capture_time_struct_tlv_direct(
            &ptr,
            payload_offset,
            p,
            0,
            TIME_DIRECT_TIMESPEC_SIZE);
        payload_size += capture_time_struct_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            p,
            1,
            TIME_DIRECT_TIMEZONE_SIZE);
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
