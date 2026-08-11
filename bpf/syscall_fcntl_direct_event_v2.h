#ifndef STRACE_GO_SYSCALL_FCNTL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FCNTL_DIRECT_EVENT_V2_H

#define FCNTL_DIRECT_SMALL_SIZE 8
#define FCNTL_DIRECT_FLOCK_SIZE 32
#define FCNTL_DIRECT_F_DUPFD 0
#define FCNTL_DIRECT_F_DUPFD_CLOEXEC 1030
#define FCNTL_DIRECT_MAX_PAYLOAD (PAYLOAD_TLV_HEADER_SIZE + FD_STATE_SNAPSHOT_SIZE)

static __always_inline int is_fcntl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_FCNTL;
}

static __always_inline int is_fcntl_fd_state_cmd(u64 cmd)
{
    u32 fcmd = (u32)cmd;
    return fcmd == FCNTL_DIRECT_F_DUPFD ||
        fcmd == FCNTL_DIRECT_F_DUPFD_CLOEXEC;
}

static __always_inline u32 fcntl_direct_payload_size(u64 cmd)
{
    u32 fcmd = (u32)cmd;
    if (fcmd == 15 || fcmd == 16 || fcmd == 1035 || fcmd == 1036 ||
        fcmd == 1037 || fcmd == 1038 || fcmd == 1039 || fcmd == 1040 ||
        fcmd == 1043 || fcmd == 1044 || fcmd == 19 || fcmd == 20 ||
        fcmd == 21 || fcmd == 22 || fcmd == 23 || fcmd == 24) {
        return FCNTL_DIRECT_SMALL_SIZE;
    }
    if (fcmd == 5 || fcmd == 6 || fcmd == 7 || fcmd == 12 ||
        fcmd == 13 || fcmd == 14 || fcmd == 36 || fcmd == 37 ||
        fcmd == 38) {
        return FCNTL_DIRECT_FLOCK_SIZE;
    }
    return 0;
}

static __always_inline u32 capture_fcntl_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 cmd,
    u64 user_ptr,
    u16 tlv_flags)
{
    u32 struct_size = fcntl_direct_payload_size(cmd);
    if (struct_size == 0 || !user_ptr) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (struct_size == FCNTL_DIRECT_SMALL_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FCNTL_DIRECT_SMALL_SIZE);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, FCNTL_DIRECT_FLOCK_SIZE);
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
            2,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_fcntl_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + FCNTL_DIRECT_MAX_PAYLOAD;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_fcntl_struct_tlv_direct(&ptr, payload_offset, ctx->args[1], ctx->args[2], 0);
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

static __always_inline void emit_fcntl_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + FCNTL_DIRECT_MAX_PAYLOAD;
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
        if (is_fcntl_fd_state_cmd(p->args[1])) {
            payload_size = capture_fd_state_tlv_direct(
                &ptr,
                payload_offset,
                (s32)ret_value);
        } else {
            payload_size = capture_fcntl_struct_tlv_direct(
                &ptr,
                payload_offset,
                p->args[1],
                p->args[2],
                PAYLOAD_TLV_FLAG_DIRECTION_OUT);
        }
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
