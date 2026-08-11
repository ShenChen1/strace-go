#ifndef STRACE_GO_SYSCALL_SIGNAL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SIGNAL_DIRECT_EVENT_V2_H

#define SIGNAL_DIRECT_SIGSET_SIZE 8
#define SIGNAL_DIRECT_SIGACTION_SIZE 32

static __always_inline int is_signal_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RT_SIGACTION || sys_id == SYS_RT_SIGPROCMASK ||
        sys_id == SYS_RT_SIGSUSPEND || sys_id == SYS_SIGNALFD ||
        sys_id == SYS_SIGNALFD4;
}

static __always_inline int is_signal_enter_direct_syscall(u32 sys_id)
{
    return is_signal_direct_syscall(sys_id);
}

static __always_inline int is_signal_exit_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RT_SIGACTION || sys_id == SYS_RT_SIGPROCMASK;
}

static __always_inline u16 signal_direct_enter_arg_index(u32 sys_id)
{
    if (sys_id == SYS_RT_SIGSUSPEND) {
        return 0;
    }
    return 1;
}

static __always_inline u32 signal_direct_struct_size(u32 sys_id)
{
    if (sys_id == SYS_RT_SIGACTION) {
        return SIGNAL_DIRECT_SIGACTION_SIZE;
    }
    return SIGNAL_DIRECT_SIGSET_SIZE;
}

static __always_inline u32 capture_signal_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u32 struct_size,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (struct_size == SIGNAL_DIRECT_SIGACTION_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, SIGNAL_DIRECT_SIGACTION_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, SIGNAL_DIRECT_SIGACTION_SIZE, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, SIGNAL_DIRECT_SIGSET_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, SIGNAL_DIRECT_SIGSET_SIZE, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_signal_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    s32 probe_ret_enter)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + SIGNAL_DIRECT_SIGACTION_SIZE;
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
    u16 arg_index = signal_direct_enter_arg_index(sys_id);
    u64 user_ptr = ctx->args[1];
    if (sys_id == SYS_RT_SIGSUSPEND) {
        user_ptr = ctx->args[0];
    }
    u32 payload_size = capture_signal_struct_tlv_direct(
        &ptr,
        payload_offset,
        arg_index,
        user_ptr,
        signal_direct_struct_size(sys_id),
        0);
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_signal_sigsuspend_marker_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    emit_signal_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns, 3);
}

static __always_inline int should_emit_signal_sigsuspend_marker(u32 tid, u32 pid)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 nr_threads = 0;
    if (task) {
        nr_threads = BPF_CORE_READ(task, signal, nr_threads);
    }
    return nr_threads > 1 && tid == pid;
}

static __always_inline void emit_signal_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + SIGNAL_DIRECT_SIGACTION_SIZE;
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
    if (ret_value >= 0 && is_signal_exit_payload_direct_syscall(p->sys_id)) {
        payload_size = capture_signal_struct_tlv_direct(
            &ptr,
            payload_offset,
            2,
            p->args[2],
            signal_direct_struct_size(p->sys_id),
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
