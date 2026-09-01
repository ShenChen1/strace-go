#ifndef STRACE_GO_SYSCALL_EVENT_CORE_V2_H
#define STRACE_GO_SYSCALL_EVENT_CORE_V2_H

static __always_inline int is_scalar_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETPID || sys_id == SYS_CLOSE || sys_id == SYS_CLOSE_RANGE;
}

static __always_inline int is_terminating_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EXIT || sys_id == SYS_EXIT_GROUP;
}

static __always_inline int is_process_creation_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CLONE || sys_id == SYS_CLONE3 ||
        sys_id == SYS_FORK || sys_id == SYS_VFORK;
}

static __always_inline int is_open_creat_path_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_OPEN || sys_id == SYS_CREAT || sys_id == SYS_OPENAT;
}

static __always_inline int is_payload_direct_syscall(u32 sys_id)
{
    return is_open_creat_path_direct_syscall(sys_id) || sys_id == SYS_WRITE || sys_id == SYS_PWRITE64 ||
        sys_id == SYS_EXECVE || sys_id == SYS_EXECVEAT;
}

static __always_inline int is_exec_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EXECVE || sys_id == SYS_EXECVEAT;
}

static __always_inline int is_write_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_WRITE || sys_id == SYS_PWRITE64;
}

static __always_inline int is_exit_payload_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_READ || sys_id == SYS_PREAD64;
}

static __always_inline int is_direct_syscall(u32 sys_id)
{
    return is_scalar_direct_syscall(sys_id) ||
        is_payload_direct_syscall(sys_id) ||
        is_exit_payload_direct_syscall(sys_id);
}

static __always_inline struct pending_task_state *lookup_pending_task_state(u64 flags)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }
    return bpf_task_storage_get(&pending_task_storage, task, 0, flags);
}

static __always_inline struct pending_task_state *current_pending_task_state(void)
{
    return lookup_pending_task_state(0);
}

static __always_inline struct pending_syscall *current_pending_syscall(void)
{
    struct pending_task_state *state = current_pending_task_state();
    return state && state->valid ? &state->syscall : 0;
}

static __always_inline u64 current_task_cpu_runtime(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) return 0;
    return BPF_CORE_READ(task, se.sum_exec_runtime);
}

static __always_inline u64 pending_syscall_cpu_duration(struct pending_syscall *pending)
{
    u64 cpu_exit_time = current_task_cpu_runtime();
    if (cpu_exit_time <= pending->cpu_enter_time) return 0;
    return cpu_exit_time - pending->cpu_enter_time;
}

static __always_inline void clear_pending_task_state(void)
{
    struct pending_task_state *state = current_pending_task_state();
    if (state) {
        if (state->valid && state->syscall.stack_id >= 0) {
            bpf_map_delete_elem(&pending_stack_map, &state->syscall.tid);
        }
        state->aux0 = 0;
        state->valid = 0;
    }
}

static __always_inline int save_pending_syscall_value(struct pending_syscall *pending)
{
    struct pending_task_state *state = lookup_pending_task_state(
        BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state) {
        record_pending_update_fail();
        return 0;
    }
    pending->cpu_enter_time = current_task_cpu_runtime();
    state->syscall = *pending;
    state->namespace_snapshot = (struct namespace_snapshot){};
    state->aux0 = 0;
    state->valid = 1;
    if (pending->stack_id >= 0 &&
        bpf_map_update_elem(&pending_stack_map, &pending->tid, &pending->stack_id, BPF_ANY) != 0) {
        record_pending_update_fail();
    }
    return 1;
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

    (void)tid;
    save_pending_syscall_value(&p);
}

static __always_inline void save_pending_syscall_aux(u32 tid, u32 aux0)
{
    struct pending_task_state *state = current_pending_task_state();
    if (!state || !state->valid) {
        record_pending_update_fail();
        return;
    }
    (void)tid;
    state->aux0 = aux0;
}

static __always_inline u32 lookup_pending_syscall_aux0(u32 tid)
{
    struct pending_task_state *state = current_pending_task_state();
    (void)tid;
    return state && state->valid ? state->aux0 : 0;
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
    capture_event_v2_comm(header);
}

static __always_inline struct event_v2_header *event_v2_header_from_dynptr_direct(
    struct bpf_dynptr *ptr)
{
    struct event_v2_header *header = bpf_dynptr_data(
        ptr,
        0,
        EVENT_V2_HEADER_LEN);
    if (!header) {
        record_ringbuf_copy_fail();
    }
    return header;
}

static __always_inline void init_syscall_enter_event_v2_from_ctx(
    struct syscall_enter_event_v2 *body,
    struct trace_event_raw_sys_enter *ctx,
    u32 payload_size,
    s64 ret_value,
    s32 probe_ret_enter,
    s32 probe_ret_exit)
{
    body->ret = ret_value;
    body->probe_ret_enter = probe_ret_enter;
    body->probe_ret_exit = probe_ret_exit;
    body->args[0] = ctx->args[0];
    body->args[1] = ctx->args[1];
    body->args[2] = ctx->args[2];
    body->args[3] = ctx->args[3];
    body->args[4] = ctx->args[4];
    body->args[5] = ctx->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void copy_syscall_enter_args(
    u64 args[6],
    struct trace_event_raw_sys_enter *ctx)
{
    args[0] = ctx->args[0];
    args[1] = ctx->args[1];
    args[2] = ctx->args[2];
    args[3] = ctx->args[3];
    args[4] = ctx->args[4];
    args[5] = ctx->args[5];
}

static __always_inline void init_syscall_enter_event_v2_from_args(
    struct syscall_enter_event_v2 *body,
    u64 args[6],
    u32 payload_size,
    s64 ret_value,
    s32 probe_ret_enter,
    s32 probe_ret_exit)
{
    body->ret = ret_value;
    body->probe_ret_enter = probe_ret_enter;
    body->probe_ret_exit = probe_ret_exit;
    body->args[0] = args[0];
    body->args[1] = args[1];
    body->args[2] = args[2];
    body->args[3] = args[3];
    body->args[4] = args[4];
    body->args[5] = args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void init_syscall_exit_event_v2_from_pending(
    struct syscall_exit_event_v2 *body,
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    u32 payload_size)
{
    body->ret = ret_value;
    body->duration_ns = duration;
    body->args[0] = p->args[0];
    body->args[1] = p->args[1];
    body->args[2] = p->args[2];
    body->args[3] = p->args[3];
    body->args[4] = p->args[4];
    body->args[5] = p->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
    body->stack_id = p->stack_id;
    body->reserved = 0;
    body->cpu_duration_ns = pending_syscall_cpu_duration(p);
}

static __always_inline void init_syscall_exit_event_v2_from_ctx(
    struct syscall_exit_event_v2 *body,
    struct trace_event_raw_sys_enter *ctx,
    s64 ret_value,
    u64 duration,
    u32 payload_size,
    s32 stack_id)
{
    body->ret = ret_value;
    body->duration_ns = duration;
    body->args[0] = ctx->args[0];
    body->args[1] = ctx->args[1];
    body->args[2] = ctx->args[2];
    body->args[3] = ctx->args[3];
    body->args[4] = ctx->args[4];
    body->args[5] = ctx->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
    body->stack_id = stack_id;
    body->reserved = 0;
    body->cpu_duration_ns = 0;
}

static __always_inline int payload_tlv_write_header_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 kind,
    u16 arg_index,
    u16 flags,
    u32 user_len,
    u32 copied_len,
    s32 probe_ret,
    u64 user_ptr)
{
    struct payload_tlv_header tlv = {};
    tlv.kind = kind;
    tlv.arg_index = arg_index;
    tlv.flags = flags;
    tlv.user_len = user_len;
    tlv.copied_len = copied_len;
    tlv.probe_ret = probe_ret;
    tlv.user_ptr = user_ptr;

    long ret = bpf_dynptr_write(ptr, payload_offset, &tlv, sizeof(tlv), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return 1;
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
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_compact_syscall_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_COMPACT_ENTER_BODY_LEN;
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
        EVENT_TYPE_ENTER,
        EVENT_FLAG_GENERIC_ENTER | EVENT_FLAG_COMPACT_ENTER,
        pid,
        tid,
        sys_id,
        out_size,
        ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_compact_enter_event_v2 body = {};
    body.args[0] = ctx->args[0];
    body.args[1] = ctx->args[1];
    body.args[2] = ctx->args[2];
    body.args[3] = ctx->args[3];
    body.args[4] = ctx->args[4];
    body.args[5] = ctx->args[5];
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_no_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    if (cfg && (*cfg & CONFIG_EMIT_ENTER)) {
        emit_syscall_enter_event_v2_direct(
            pid,
            tid,
            sys_id,
            ctx,
            EVENT_FLAG_GENERIC_ENTER,
            ts_ns);
    }
}

static __always_inline void emit_plain_no_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    if (!cfg || !(*cfg & CONFIG_EMIT_ENTER)) {
        return;
    }
    if (*cfg & CONFIG_ELIDE_PLAIN_ENTER) {
        u32 *elide = bpf_map_lookup_elem(&plain_enter_elide_map, &sys_id);
        if (elide) {
            return;
        }
    }
    emit_compact_syscall_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
}

static __always_inline void emit_terminating_exit_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    s32 stack_id)
{
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, 0, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_ctx(&body, ctx, 0, 0, 0, stack_id);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
