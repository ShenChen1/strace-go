#ifndef STRACE_GO_SYSCALL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_DIRECT_EVENT_V2_H

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
    struct trace_event_raw_sys_enter *ctx)
{
    body->args[0] = ctx->args[0];
    body->args[1] = ctx->args[1];
    body->args[2] = ctx->args[2];
    body->args[3] = ctx->args[3];
    body->args[4] = ctx->args[4];
    body->args[5] = ctx->args[5];
    body->capture_len = 0;
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
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
