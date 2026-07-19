#ifndef STRACE_GO_SYSCALL_CAPABILITY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_CAPABILITY_DIRECT_EVENT_V2_H

#define CAPABILITY_DIRECT_HEADER_SIZE 8
#define CAPABILITY_DIRECT_WORD_SIZE 12
#define CAPABILITY_DIRECT_DATA_SIZE 24
#define CAPABILITY_VERSION_1 0x19980330
#define CAPABILITY_VERSION_2 0x20071026
#define CAPABILITY_VERSION_3 0x20080522

static __always_inline int is_capability_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CAPGET || sys_id == SYS_CAPSET;
}

static __always_inline u32 capability_direct_data_size(u32 version)
{
    if (version == CAPABILITY_VERSION_1) {
        return CAPABILITY_DIRECT_WORD_SIZE;
    }
    if (version == CAPABILITY_VERSION_2 || version == CAPABILITY_VERSION_3) {
        return CAPABILITY_DIRECT_DATA_SIZE;
    }
    return 0;
}

static __always_inline s32 capability_direct_probe_ret_for_arg(u16 arg_index)
{
    return -((1 << arg_index) + 1);
}

static __always_inline void *capability_direct_dynptr_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 struct_size)
{
    if (struct_size == CAPABILITY_DIRECT_HEADER_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, CAPABILITY_DIRECT_HEADER_SIZE);
    }
    if (struct_size == CAPABILITY_DIRECT_WORD_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, CAPABILITY_DIRECT_WORD_SIZE);
    }
    return bpf_dynptr_data(ptr, data_offset, CAPABILITY_DIRECT_DATA_SIZE);
}

static __always_inline u32 capture_capability_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u16 tlv_flags,
    u64 user_ptr,
    u32 struct_size)
{
    if (!user_ptr || struct_size == 0) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = capability_direct_dynptr_data(ptr, data_offset, struct_size);
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
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_capability_header_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 *version,
    s32 *probe_ret_enter)
{
    u32 size = capture_capability_struct_tlv_direct(
        ptr,
        payload_offset,
        0,
        0,
        user_ptr,
        CAPABILITY_DIRECT_HEADER_SIZE);
    if (size == PAYLOAD_TLV_HEADER_SIZE + CAPABILITY_DIRECT_HEADER_SIZE) {
        long err = bpf_probe_read_user(version, sizeof(*version), (void *)user_ptr);
        *probe_ret_enter = err < 0 ? capability_direct_probe_ret_for_arg(0) : 0;
    } else if (user_ptr) {
        *probe_ret_enter = capability_direct_probe_ret_for_arg(0);
    }
    return size;
}

static __always_inline void emit_capability_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + CAPABILITY_DIRECT_HEADER_SIZE;
    if (sys_id == SYS_CAPSET) {
        payload_capacity += PAYLOAD_TLV_HEADER_SIZE + CAPABILITY_DIRECT_DATA_SIZE;
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
    u32 header_version = 0;
    s32 probe_ret_enter = -1;
    u32 payload_size = capture_capability_header_tlv_direct(
        &ptr,
        payload_offset,
        ctx->args[0],
        &header_version,
        &probe_ret_enter);
    if (sys_id == SYS_CAPSET && probe_ret_enter == 0) {
        payload_size += capture_capability_struct_tlv_direct(
            &ptr,
            payload_offset + payload_size,
            1,
            0,
            ctx->args[1],
            capability_direct_data_size(header_version));
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, probe_ret_enter, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_capability_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + CAPABILITY_DIRECT_DATA_SIZE;
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
    u32 payload_size = capture_capability_struct_tlv_direct(
        &ptr,
        payload_offset,
        1,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        p->args[1],
        CAPABILITY_DIRECT_DATA_SIZE);
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
