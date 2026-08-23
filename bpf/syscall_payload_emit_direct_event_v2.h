#ifndef STRACE_GO_SYSCALL_PAYLOAD_EMIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PAYLOAD_EMIT_DIRECT_EVENT_V2_H

static __always_inline void emit_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 args[6] = {};
    copy_syscall_enter_args(args, ctx);
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_OPENAT_MAX;
    if (is_write_payload_direct_syscall(sys_id)) {
        payload_capacity = PAYLOAD_TLV_HEADER_SIZE +
            payload_tlv_data_bucket(payload_tlv_copy_len(args[2], PAYLOAD_TLV_WRITE_MAX));
    } else if (is_exec_payload_direct_syscall(sys_id)) {
        payload_capacity = PAYLOAD_TLV_HEADER_SIZE + sizeof(struct exec_snapshot) +
            PAYLOAD_TLV_HEADER_SIZE + EXEC_PATH_SNAPSHOT_MAX;
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
    u32 payload_size = capture_payload_tlv_direct(&ptr, payload_offset, sys_id, args, &flags);
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
    init_syscall_enter_event_v2_from_args(&body, args, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_exec_enter_event_v2_direct_with_status(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 base_flags,
    s64 ret_value,
    s32 probe_ret_enter)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return;
    }
    copy_syscall_enter_args(scratch->args, ctx);
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + sizeof(struct exec_snapshot) +
        PAYLOAD_TLV_HEADER_SIZE + EXEC_PATH_SNAPSHOT_MAX;
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

    u16 flags = base_flags;
    u32 payload_size = capture_payload_tlv_direct(&ptr, payload_offset, sys_id, scratch->args, &flags);
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
    init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, ret_value, probe_ret_enter, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_exec_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns,
    s32 probe_ret_enter)
{
    if (cfg && (*cfg & CONFIG_EMIT_ENTER)) {
        emit_exec_enter_event_v2_direct_with_status(
            pid,
            tid,
            sys_id,
            ctx,
            ts_ns,
            EVENT_FLAG_GENERIC_ENTER,
            0,
            -1);
    }
    emit_exec_enter_event_v2_direct_with_status(
        pid,
        tid,
        sys_id,
        ctx,
        ts_ns,
        0,
        -514,
        probe_ret_enter);
}

static __always_inline void emit_syscall_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    u16 flags)
{
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, 0);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_open_creat_fd_state_path_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u16 path_arg = p->sys_id == SYS_OPENAT ? 1 : 0;
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_OPENAT_MAX;
    if (ret_value >= 0) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + FD_STATE_SNAPSHOT_SIZE;
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
    u32 payload_size = capture_openat_path_tlv_direct(
        &ptr,
        payload_offset,
        path_arg,
        p->args[path_arg]);
    if (ret_value >= 0) {
        payload_size += capture_fd_state_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            (s32)ret_value);
    }
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
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

static __always_inline void emit_payload_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = 0;
    if (ret_value > 0) {
        payload_capacity = PAYLOAD_TLV_HEADER_SIZE +
            payload_tlv_data_bucket(
                payload_tlv_copy_len((u64)ret_value, PAYLOAD_TLV_READ_MAX));
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
    u32 payload_size = capture_read_bytes_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
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

static __always_inline void emit_exec_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + sizeof(struct exec_snapshot) +
        PAYLOAD_TLV_HEADER_SIZE + EXEC_PATH_SNAPSHOT_MAX;
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
    if (p->sys_id == SYS_EXECVE) {
        struct exec_capture_request request = {};
        request.ptr = &ptr;
        request.payload_offset = payload_offset;
        request.path_index = 0;
        request.argv_index = 1;
        request.path_ptr = p->args[0];
        request.argv_ptr = p->args[1];
        request.env_ptr = p->args[2];
        payload_size = capture_exec_tlv_direct(&request);
    } else if (p->sys_id == SYS_EXECVEAT) {
        struct exec_capture_request request = {};
        request.ptr = &ptr;
        request.payload_offset = payload_offset;
        request.path_index = 1;
        request.argv_index = 2;
        request.path_ptr = p->args[1];
        request.argv_ptr = p->args[2];
        request.env_ptr = p->args[3];
        payload_size = capture_exec_tlv_direct(&request);
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
