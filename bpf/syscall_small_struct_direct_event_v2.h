#ifndef STRACE_GO_SYSCALL_SMALL_STRUCT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SMALL_STRUCT_DIRECT_EVENT_V2_H

#define SMALL_STRUCT_DIRECT_WORD_SIZE 8
#define SMALL_STRUCT_DIRECT_MAX_SECTIONS 2
#define SMALL_STRUCT_DIRECT_MAX_PAYLOAD \
    (SMALL_STRUCT_DIRECT_MAX_SECTIONS * (PAYLOAD_TLV_HEADER_SIZE + SMALL_STRUCT_DIRECT_WORD_SIZE))

static __always_inline int is_arch_prctl_get_direct_option(u64 option)
{
    return option == 0x1003 || option == 0x1004 || option == 0x1011 ||
        option == 0x1021 || option == 0x1022 || option == 0x1024;
}

static __always_inline int is_small_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||
        sys_id == SYS_GET_ROBUST_LIST || sys_id == SYS_COPY_FILE_RANGE;
}

static __always_inline int is_small_struct_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_COPY_FILE_RANGE;
}

static __always_inline int is_small_struct_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||
        sys_id == SYS_GET_ROBUST_LIST;
}

static __always_inline u32 capture_small_struct_word_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = SMALL_STRUCT_DIRECT_WORD_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, SMALL_STRUCT_DIRECT_WORD_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, SMALL_STRUCT_DIRECT_WORD_SIZE, (void *)user_ptr);
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
            tlv_flags,
            SMALL_STRUCT_DIRECT_WORD_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_small_struct_enter_event_v2_direct_with_arg(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 arg_index,
    u64 user_ptr)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + SMALL_STRUCT_DIRECT_MAX_PAYLOAD;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_small_struct_word_tlv_direct(&ptr, payload_offset, arg_index, user_ptr, 0);
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

static __always_inline void emit_copy_file_range_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + SMALL_STRUCT_DIRECT_MAX_PAYLOAD;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_small_struct_word_tlv_direct(&ptr, payload_offset, 1, ctx->args[1], 0);
    payload_size += capture_small_struct_word_tlv_direct(&ptr, payload_offset + payload_size, 3, ctx->args[3], 0);
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

static __always_inline void emit_small_struct_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    if (sys_id == SYS_COPY_FILE_RANGE) {
        emit_copy_file_range_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    emit_small_struct_enter_event_v2_direct_with_arg(pid, tid, sys_id, ctx, ts_ns, 2, ctx->args[2]);
}

static __always_inline void emit_small_struct_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + SMALL_STRUCT_DIRECT_MAX_PAYLOAD;
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
    if (p->sys_id == SYS_GET_ROBUST_LIST) {
        payload_size = capture_small_struct_word_tlv_direct(
            &ptr,
            payload_offset,
            1,
            p->args[1],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
        payload_size += capture_small_struct_word_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            2,
            p->args[2],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    } else if (p->sys_id == SYS_SENDFILE) {
        payload_size = capture_small_struct_word_tlv_direct(
            &ptr,
            payload_offset,
            2,
            p->args[2],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    } else if (p->sys_id == SYS_ARCH_PRCTL && is_arch_prctl_get_direct_option(p->args[0])) {
        payload_size = capture_small_struct_word_tlv_direct(
            &ptr,
            payload_offset,
            1,
            p->args[1],
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
