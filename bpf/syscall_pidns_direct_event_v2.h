#ifndef STRACE_GO_SYSCALL_PIDNS_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PIDNS_DIRECT_EVENT_V2_H

#define PID_NAMESPACE_MAX_LEVEL 32

static __always_inline int read_pid_namespace_number(
    struct pid *pid,
    struct pid_namespace_config *config,
    u32 *number)
{
    if (!pid || !config || !config->ready ||
        config->level > PID_NAMESPACE_MAX_LEVEL) {
        return 0;
    }
    u32 pid_level = BPF_CORE_READ(pid, level);
    if (config->level > pid_level) return 0;

    struct upid upid = {};
    long ret = bpf_probe_read_kernel(
        &upid,
        sizeof(upid),
        &pid->numbers[config->level]);
    if (ret < 0 || !upid.ns || upid.nr <= 0) return 0;
    if (BPF_CORE_READ(upid.ns, ns.inum) != config->inum) return 0;

    *number = (u32)upid.nr;
    return 1;
}

static __always_inline void capture_tracer_pid_namespace(
    struct trace_event_raw_sys_enter *ctx,
    u32 sys_id)
{
    u32 key = 0;
    struct pid_namespace_config *config =
        bpf_map_lookup_elem(&pid_namespace_config_map, &key);
    if (!config || !config->nonce || config->ready || sys_id != SYS_GETPGID ||
        (u32)ctx->args[0] != config->nonce) {
        return;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct pid *pid = task ? BPF_CORE_READ(task, thread_pid) : 0;
    if (!pid) return;
    u32 level = BPF_CORE_READ(pid, level);
    if (level > PID_NAMESPACE_MAX_LEVEL) return;

    struct upid upid = {};
    long ret = bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[level]);
    if (ret < 0 || !upid.ns) return;
    config->level = level;
    config->inum = BPF_CORE_READ(upid.ns, ns.inum);
    config->ready = config->inum != 0;
}

static __always_inline int read_pid_namespace_snapshot(
    struct pending_syscall *pending,
    struct pid_namespace_snapshot *snapshot)
{
    u32 key = 0;
    struct pid_namespace_config *config =
        bpf_map_lookup_elem(&pid_namespace_config_map, &key);
    if (!config || !config->ready) return 0;
    if (config->level == 0) {
        snapshot->tid = pending->tid;
        snapshot->tgid = pending->pid;
        return 1;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct pid *tid_pid = task ? BPF_CORE_READ(task, thread_pid) : 0;
    if (pending->sys_id == SYS_GETTID) {
        return read_pid_namespace_number(tid_pid, config, &snapshot->tid);
    }
    struct task_struct *leader = task ? BPF_CORE_READ(task, group_leader) : 0;
    struct pid *tgid_pid = leader ? BPF_CORE_READ(leader, thread_pid) : 0;
    return read_pid_namespace_number(tgid_pid, config, &snapshot->tgid);
}

static __always_inline int capture_pid_namespace_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pid_namespace_snapshot *snapshot)
{
    long ret = bpf_dynptr_write(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        snapshot,
        sizeof(*snapshot),
        0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return payload_tlv_write_header_direct(
        ptr,
        payload_offset,
        PAYLOAD_TLV_KIND_PID_NAMESPACE,
        PAYLOAD_TLV_PID_NAMESPACE_ARG_INDEX,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        sizeof(*snapshot),
        sizeof(*snapshot),
        0,
        0);
}

static __always_inline void emit_pid_namespace_exit_event_v2_direct(
    struct pending_syscall *pending,
    s64 ret_value,
    u64 duration)
{
    struct pid_namespace_snapshot snapshot = {};
    if (ret_value <= 0 || !read_pid_namespace_snapshot(pending, &snapshot)) {
        emit_syscall_exit_event_v2_direct(pending, ret_value, duration, 0);
        return;
    }

    u32 payload_size = PAYLOAD_TLV_HEADER_SIZE + PID_NAMESPACE_SNAPSHOT_SIZE;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_size;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    if (!capture_pid_namespace_tlv_direct(&ptr, payload_offset, &snapshot)) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        EVENT_FLAG_PAYLOAD_TLV,
        pending->pid,
        pending->tid,
        pending->sys_id,
        out_size,
        pending->enter_time + duration);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body,
        pending,
        ret_value,
        duration,
        payload_size);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
