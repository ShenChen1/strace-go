#ifndef STRACE_GO_SYSCALL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_DIRECT_EVENT_V2_H

static __always_inline int is_scalar_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETPID || sys_id == SYS_CLOSE;
}

static __always_inline int is_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_OPENAT || sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;
}

static __always_inline int is_write_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;
}

static __always_inline int is_direct_syscall(u32 sys_id)
{
    return is_scalar_direct_syscall(sys_id) || is_payload_direct_syscall(sys_id);
}

static __always_inline void save_pending_syscall_args(
    u32 tid,
    u32 pid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 enter_time,
    s32 stack_id)
{
    struct pending_syscall p = {};

    p.enter_time = enter_time;
    p.args[0] = ctx->args[0];
    p.args[1] = ctx->args[1];
    p.args[2] = ctx->args[2];
    p.args[3] = ctx->args[3];
    p.args[4] = ctx->args[4];
    p.args[5] = ctx->args[5];
    p.pid = pid;
    p.sys_id = sys_id;
    p.tid = tid;
    p.stack_id = stack_id;

    bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY);
}

static __always_inline void init_syscall_event_v2_header_direct(
    struct event_v2_header *header,
    u16 event_type,
    u16 flags,
    u32 pid,
    u32 tid,
    u32 sys_id,
    u32 out_size,
    u64 ts_ns)
{
    header->version = EVENT_VERSION;
    header->event_type = event_type;
    header->flags = flags;
    header->header_len = EVENT_V2_HEADER_LEN;
    header->size = out_size;
    header->pid = pid;
    header->tid = tid;
    header->sys_id = sys_id;
    header->seq = 0;
    header->ts_ns = ts_ns;
}

static __always_inline void init_syscall_enter_event_v2_from_ctx(
    struct syscall_enter_event_v2 *body,
    struct trace_event_raw_sys_enter *ctx,
    u32 payload_size)
{
    body->args[0] = ctx->args[0];
    body->args[1] = ctx->args[1];
    body->args[2] = ctx->args[2];
    body->args[3] = ctx->args[3];
    body->args[4] = ctx->args[4];
    body->args[5] = ctx->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void init_syscall_exit_event_v2_from_pending(
    struct syscall_exit_event_v2 *body,
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    body->ret = ret_value;
    body->duration_ns = duration;
    body->args[0] = p->args[0];
    body->args[1] = p->args[1];
    body->args[2] = p->args[2];
    body->args[3] = p->args[3];
    body->args[4] = p->args[4];
    body->args[5] = p->args[5];
    body->capture_len = 0;
    body->capture_flags = 0;
}

static __always_inline void emit_syscall_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 flags,
    u64 ts_ns)
{
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline u32 capture_openat_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_OPENAT_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, PAYLOAD_TLV_OPENAT_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > PAYLOAD_TLV_OPENAT_MAX) {
                copied_len = PAYLOAD_TLV_OPENAT_MAX;
            } else {
                copied_len = (u32)n;
            }
        }
    }

    struct payload_tlv_header tlv = {};
    tlv.kind = PAYLOAD_TLV_KIND_STRING;
    tlv.arg_index = 1;
    tlv.user_len = copied_len;
    tlv.copied_len = copied_len;
    tlv.probe_ret = probe_ret;
    tlv.user_ptr = user_ptr;

    long ret = bpf_dynptr_write(ptr, payload_offset, &tlv, sizeof(tlv), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_write_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 user_ptr = ctx->args[1];
    u32 user_len = payload_tlv_clamp_u32(ctx->args[2]);
    u32 copied_len = payload_tlv_copy_len(ctx->args[2], PAYLOAD_TLV_WRITE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (copied_len > 0) {
        if (!user_ptr) {
            probe_ret = -1;
            copied_len = 0;
        } else {
            void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_WRITE_MAX);
            if (!payload_data) {
                record_ringbuf_copy_fail();
                probe_ret = -1;
                copied_len = 0;
            } else {
                long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
                if (err < 0) {
                    probe_ret = err;
                    copied_len = 0;
                }
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    struct payload_tlv_header tlv = {};
    tlv.kind = PAYLOAD_TLV_KIND_BYTES;
    tlv.arg_index = 1;
    tlv.user_len = user_len;
    tlv.copied_len = copied_len;
    tlv.probe_ret = probe_ret;
    tlv.user_ptr = user_ptr;

    long ret = bpf_dynptr_write(ptr, payload_offset, &tlv, sizeof(tlv), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (sys_id == SYS_OPENAT) {
        return capture_openat_path_tlv_direct(ptr, payload_offset, ctx->args[1]);
    }
    if (is_write_payload_direct_syscall(sys_id)) {
        return capture_write_bytes_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    return 0;
}

static __always_inline void emit_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_OPENAT_MAX;
    if (is_write_payload_direct_syscall(sys_id)) {
        payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PAYLOAD_TLV_WRITE_MAX;
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
    u32 payload_size = capture_payload_tlv_direct(&ptr, payload_offset, sys_id, ctx, &flags);
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
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
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
