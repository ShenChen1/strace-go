#ifndef STRACE_GO_SYSCALL_SLEEP_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SLEEP_DIRECT_EVENT_V2_H

static __always_inline u16 sleep_request_arg_index(u32 sys_id)
{
    if (sys_id == SYS_CLOCK_NANOSLEEP) {
        return 2;
    }
    return 0;
}

static __always_inline u16 sleep_remaining_arg_index(u32 sys_id)
{
    if (sys_id == SYS_CLOCK_NANOSLEEP) {
        return 3;
    }
    return 1;
}

static __always_inline int is_sleep_interrupted_ret(s64 ret_value)
{
    return ret_value == -516 || ret_value == -4;
}

static __always_inline int should_emit_nanosleep_suspended_marker(u32 tid, u32 pid)
{
    if (tid != pid) {
        return 0;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    u32 nr_threads = BPF_CORE_READ(task, signal, nr_threads);
    return nr_threads > 1;
}

static __always_inline void emit_sleep_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 request_arg_index,
    u64 request_user_ptr,
    s32 probe_ret_enter)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + TIME_DIRECT_TIMESPEC_SIZE;
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
    u32 payload_size = capture_time_struct_tlv_direct_from_ptr(
        &ptr,
        payload_offset,
        request_arg_index,
        request_user_ptr,
        TIME_DIRECT_TIMESPEC_SIZE,
        0);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline u64 sleep_remaining_user_ptr(struct pending_syscall *p)
{
    if (p->sys_id == SYS_CLOCK_NANOSLEEP) {
        return p->args[3];
    }
    return p->args[1];
}

static __always_inline void emit_sleep_exit_event_v2_direct(
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
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = 0;
    if (is_sleep_interrupted_ret(ret_value)) {
        payload_size = capture_time_struct_tlv_direct_from_ptr(
            &ptr,
            payload_offset,
            sleep_remaining_arg_index(p->sys_id),
            sleep_remaining_user_ptr(p),
            TIME_DIRECT_TIMESPEC_SIZE,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    }
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
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
