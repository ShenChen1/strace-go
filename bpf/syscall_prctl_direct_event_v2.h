#ifndef STRACE_GO_SYSCALL_PRCTL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PRCTL_DIRECT_EVENT_V2_H

#define PRCTL_DIRECT_NAME_SIZE 16
#define PRCTL_DIRECT_UINT32_SIZE 4
#define PRCTL_OPTION_GET_PDEATHSIG 1
#define PRCTL_OPTION_SET_NAME 15
#define PRCTL_OPTION_GET_NAME 16

static __always_inline int is_prctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PRCTL;
}

static __always_inline int is_prctl_set_name_option(u64 option)
{
    return option == PRCTL_OPTION_SET_NAME;
}

static __always_inline int is_prctl_get_name_option(u64 option)
{
    return option == PRCTL_OPTION_GET_NAME;
}

static __always_inline int is_prctl_uint32_out_option(u64 option)
{
    return option == PRCTL_OPTION_GET_PDEATHSIG || option == 5 ||
        option == 9 || option == 11 || option == 19 ||
        option == 25 || option == 37;
}

static __always_inline u32 capture_prctl_name_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 user_len = 0;
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, PRCTL_DIRECT_NAME_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, PRCTL_DIRECT_NAME_SIZE, (void *)user_ptr);
        if (n < 0) {
            if (tlv_flags & PAYLOAD_TLV_FLAG_DIRECTION_OUT) {
                probe_ret = n;
            } else {
                long raw_n = bpf_probe_read_user(
                    payload_data,
                    PRCTL_DIRECT_NAME_SIZE - 1,
                    (void *)user_ptr);
                if (raw_n < 0) {
                    probe_ret = n;
                } else {
                    user_len = PRCTL_DIRECT_NAME_SIZE;
                    copied_len = PRCTL_DIRECT_NAME_SIZE - 1;
                }
            }
        } else if (n >= PRCTL_DIRECT_NAME_SIZE && !(tlv_flags & PAYLOAD_TLV_FLAG_DIRECTION_OUT)) {
            user_len = PRCTL_DIRECT_NAME_SIZE;
            copied_len = PRCTL_DIRECT_NAME_SIZE - 1;
        } else {
            copied_len = (u32)n;
            user_len = copied_len;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            1,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_prctl_uint32_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = PRCTL_DIRECT_UINT32_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, PRCTL_DIRECT_UINT32_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, PRCTL_DIRECT_UINT32_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            PRCTL_DIRECT_UINT32_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_prctl_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PRCTL_DIRECT_NAME_SIZE;
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
    if (is_prctl_set_name_option(ctx->args[0])) {
        payload_size = capture_prctl_name_tlv_direct(&ptr, payload_offset, ctx->args[1], 0);
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

static __always_inline void emit_prctl_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PRCTL_DIRECT_NAME_SIZE;
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
    if (ret_value >= 0 && is_prctl_get_name_option(p->args[0])) {
        payload_size = capture_prctl_name_tlv_direct(
            &ptr,
            payload_offset,
            p->args[1],
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    } else if (ret_value >= 0 && is_prctl_uint32_out_option(p->args[0])) {
        payload_size = capture_prctl_uint32_tlv_direct(&ptr, payload_offset, p->args[1]);
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
