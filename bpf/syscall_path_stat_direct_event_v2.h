#ifndef STRACE_GO_SYSCALL_PATH_STAT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PATH_STAT_DIRECT_EVENT_V2_H

#define PATH_STAT_DIRECT_PATH_MAX 512

static __always_inline int is_path_stat_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_STAT || sys_id == SYS_LSTAT || sys_id == SYS_STATFS || sys_id == SYS_NEWFSTATAT;
}

static __always_inline u32 capture_path_stat_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 path_arg,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PATH_STAT_DIRECT_PATH_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, PATH_STAT_DIRECT_PATH_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > PATH_STAT_DIRECT_PATH_MAX) {
                copied_len = PATH_STAT_DIRECT_PATH_MAX;
            } else {
                copied_len = (u32)n;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            path_arg,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_path_stat_enter_event_v2_direct_with_path(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 path_arg,
    u64 user_ptr)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PATH_STAT_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    body.ret = 0;
    body.probe_ret_enter = -1;
    body.probe_ret_exit = -1;
    body.args[0] = ctx->args[0];
    body.args[1] = ctx->args[1];
    body.args[2] = ctx->args[2];
    body.args[3] = ctx->args[3];
    body.args[4] = ctx->args[4];
    body.args[5] = ctx->args[5];
    body.capture_len = 0;
    body.capture_flags = 0;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_path_stat_path_tlv_direct(&ptr, payload_offset, path_arg, user_ptr);
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

    body.capture_len = payload_size;
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_path_stat_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    if (sys_id == SYS_NEWFSTATAT) {
        emit_path_stat_enter_event_v2_direct_with_path(pid, tid, sys_id, ctx, ts_ns, 1, ctx->args[1]);
        return;
    }
    emit_path_stat_enter_event_v2_direct_with_path(pid, tid, sys_id, ctx, ts_ns, 0, ctx->args[0]);
}

#endif
