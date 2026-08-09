#ifndef STRACE_GO_SYSCALL_QUOTA_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_QUOTA_DIRECT_EVENT_V2_H

#define QUOTA_DIRECT_DQBLK_SIZE 72
#define QUOTA_DIRECT_DQINFO_SIZE 24
#define QUOTA_DIRECT_FORMAT_SIZE 4

#define QUOTA_DIRECT_SYNC 0x800001
#define QUOTA_DIRECT_ON 0x800002
#define QUOTA_DIRECT_OFF 0x800003
#define QUOTA_DIRECT_GETFMT 0x800004
#define QUOTA_DIRECT_GETINFO 0x800005
#define QUOTA_DIRECT_SETINFO 0x800006
#define QUOTA_DIRECT_GETQUOTA 0x800007
#define QUOTA_DIRECT_SETQUOTA 0x800008
#define QUOTA_DIRECT_GETNEXTQUOTA 0x800009

static __always_inline int is_quota_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_QUOTACTL || sys_id == SYS_QUOTACTL_FD;
}

static __always_inline u32 quota_direct_command(u64 qcmd)
{
    return (u32)qcmd >> 8;
}

static __always_inline u32 quota_direct_enter_command(
    struct trace_event_raw_sys_enter *ctx,
    u32 sys_id)
{
    volatile u64 arg0 = ctx->args[0];
    volatile u64 arg1 = ctx->args[1];
    return quota_direct_command(sys_id == SYS_QUOTACTL_FD ? arg1 : arg0);
}

static __always_inline u32 quota_direct_pending_command(struct pending_syscall *p)
{
    u64 qcmd = p->args[0];
    if (p->sys_id == SYS_QUOTACTL_FD) {
        qcmd = p->args[1];
    }
    return quota_direct_command(qcmd);
}

static __always_inline int quota_direct_has_exit_payload(u32 command)
{
    return command == QUOTA_DIRECT_GETFMT || command == QUOTA_DIRECT_GETINFO ||
        command == QUOTA_DIRECT_GETQUOTA || command == QUOTA_DIRECT_GETNEXTQUOTA;
}

static __always_inline u32 quota_direct_struct_size(u32 command)
{
    if (command == QUOTA_DIRECT_GETFMT) {
        return QUOTA_DIRECT_FORMAT_SIZE;
    }
    if (command == QUOTA_DIRECT_GETINFO || command == QUOTA_DIRECT_SETINFO) {
        return QUOTA_DIRECT_DQINFO_SIZE;
    }
    return QUOTA_DIRECT_DQBLK_SIZE;
}

static __always_inline void *quota_direct_dynptr_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 struct_size)
{
    if (struct_size == QUOTA_DIRECT_FORMAT_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_FORMAT_SIZE);
    }
    if (struct_size == QUOTA_DIRECT_DQINFO_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_DQINFO_SIZE);
    }
    return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_DQBLK_SIZE);
}

static __always_inline u32 capture_quota_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
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
    void *payload_data = quota_direct_dynptr_data(ptr, data_offset, struct_size);
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
            3,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 quota_direct_enter_capacity(u32 sys_id, u32 command)
{
    u32 capacity = 0;
    if (sys_id == SYS_QUOTACTL) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    }
    if (command == QUOTA_DIRECT_ON) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    } else if (command == QUOTA_DIRECT_SETINFO || command == QUOTA_DIRECT_SETQUOTA) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + quota_direct_struct_size(command);
    }
    return capacity;
}

static __always_inline u32 capture_quota_enter_tlvs(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx)
{
    u32 payload_size = 0;
    u32 command = quota_direct_enter_command(ctx, sys_id);
    if (sys_id == SYS_QUOTACTL) {
        payload_size = capture_path_only_tlv_direct(ptr, payload_offset, 1, ctx->args[1]);
    }
    if (command == QUOTA_DIRECT_ON) {
        payload_size += capture_path_only_tlv_direct(
            ptr, payload_offset + payload_size, 3, ctx->args[3]);
    } else if (command == QUOTA_DIRECT_SETINFO || command == QUOTA_DIRECT_SETQUOTA) {
        payload_size += capture_quota_struct_tlv_direct(
            ptr,
            payload_offset + payload_size,
            ctx->args[3],
            quota_direct_struct_size(command),
            0);
    }
    return payload_size;
}

static __always_inline void emit_quota_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 command = quota_direct_enter_command(ctx, sys_id);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + quota_direct_enter_capacity(sys_id, command);
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u32 payload_size = capture_quota_enter_tlvs(&ptr, payload_offset, sys_id, ctx);
    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
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

static __always_inline void emit_quota_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 command = quota_direct_pending_command(p);
    u32 struct_size = quota_direct_struct_size(command);
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + struct_size;
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

    u32 payload_size = capture_quota_struct_tlv_direct(
        &ptr,
        payload_offset,
        p->args[3],
        struct_size,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    u16 flags = payload_size > 0 ? EVENT_FLAG_PAYLOAD_TLV : 0;
    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
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
