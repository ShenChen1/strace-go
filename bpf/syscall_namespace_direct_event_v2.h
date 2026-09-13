#ifndef STRACE_GO_SYSCALL_NAMESPACE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NAMESPACE_DIRECT_EVENT_V2_H

#define CLONE_NEWCGROUP_VALUE 0x02000000ULL
#define CLONE_NEWIPC_VALUE 0x08000000ULL
#define CLONE_NEWNS_VALUE 0x00020000ULL
#define CLONE_NEWNET_VALUE 0x40000000ULL
#define CLONE_NEWPID_VALUE 0x20000000ULL
#define CLONE_NEWTIME_VALUE 0x00000080ULL
#define CLONE_NEWUTS_VALUE 0x04000000ULL
#define CLONE_NEWUSER_VALUE 0x10000000ULL
#define CLONE_INTO_CGROUP_VALUE 0x200000000ULL
#define NAMESPACE_FLAG_MASK (CLONE_NEWCGROUP_VALUE | CLONE_NEWIPC_VALUE | \
    CLONE_NEWNS_VALUE | CLONE_NEWNET_VALUE | CLONE_NEWPID_VALUE | \
    CLONE_NEWTIME_VALUE | CLONE_NEWUTS_VALUE | CLONE_NEWUSER_VALUE | \
    CLONE_INTO_CGROUP_VALUE)
#define NAMESPACE_PROBE_READ_FAILED (-14)
#define PID_NAMESPACE_MAX_LEVEL 32

static __always_inline s32 read_active_pid_namespace_id(
    struct task_struct *task,
    u32 *id)
{
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid) return NAMESPACE_PROBE_READ_FAILED;

    u32 level = BPF_CORE_READ(pid, level);
    if (level > PID_NAMESPACE_MAX_LEVEL) return NAMESPACE_PROBE_READ_FAILED;

    struct pid_namespace *ns = 0;
    long ret = bpf_probe_read_kernel(
        &ns,
        sizeof(ns),
        &pid->numbers[level].ns);
    if (ret < 0 || !ns) return NAMESPACE_PROBE_READ_FAILED;
    *id = BPF_CORE_READ(ns, ns.inum);
    return 0;
}

static __always_inline s32 read_namespace_snapshot(
    struct task_struct *task,
    u64 flags,
    struct namespace_snapshot *snapshot)
{
    if (!task || !snapshot) return NAMESPACE_PROBE_READ_FAILED;
    struct nsproxy *proxy = BPF_CORE_READ(task, nsproxy);
    const struct cred *cred = BPF_CORE_READ(task, cred);
    if (!proxy || !cred) return NAMESPACE_PROBE_READ_FAILED;

    struct cgroup_namespace *cgroup = BPF_CORE_READ(proxy, cgroup_ns);
    struct ipc_namespace *ipc = BPF_CORE_READ(proxy, ipc_ns);
    struct mnt_namespace *mnt = BPF_CORE_READ(proxy, mnt_ns);
    struct net *net = BPF_CORE_READ(proxy, net_ns);
    struct time_namespace *time = BPF_CORE_READ(proxy, time_ns);
    struct uts_namespace *uts = BPF_CORE_READ(proxy, uts_ns);
    struct user_namespace *user = BPF_CORE_READ(cred, user_ns);

    *snapshot = (struct namespace_snapshot){
        .flags = flags,
        .cgroup = cgroup ? BPF_CORE_READ(cgroup, ns.inum) : 0,
        .ipc = ipc ? BPF_CORE_READ(ipc, ns.inum) : 0,
        .mnt = mnt ? BPF_CORE_READ(mnt, ns.inum) : 0,
        .net = net ? BPF_CORE_READ(net, ns.inum) : 0,
        .time = time ? BPF_CORE_READ(time, ns.inum) : 0,
        .uts = uts ? BPF_CORE_READ(uts, ns.inum) : 0,
        .user = user ? BPF_CORE_READ(user, ns.inum) : 0,
    };
    if (read_active_pid_namespace_id(task, &snapshot->pid) < 0) {
        snapshot->pid = 0;
    }
    return 0;
}

static __always_inline int namespace_snapshot_for_exit(
    struct pending_syscall *pending,
    struct namespace_snapshot *snapshot)
{
    if (pending->sys_id == SYS_CLONE || pending->sys_id == SYS_CLONE3) {
        struct pending_task_state *state = current_pending_task_state();
        if (!state || !state->valid) return 0;
        *snapshot = state->namespace_snapshot;
        return (snapshot->flags & NAMESPACE_FLAG_MASK) != 0;
    }

    u64 flags = 0;
    if (pending->sys_id == SYS_SETNS) {
        flags = pending->args[1];
    } else if (pending->sys_id == SYS_UNSHARE) {
        flags = pending->args[0];
    } else {
        return 0;
    }
    if (!(flags & NAMESPACE_FLAG_MASK)) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return read_namespace_snapshot(task, flags, snapshot) == 0;
}

static __always_inline int capture_namespace_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct namespace_snapshot *snapshot)
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
        PAYLOAD_TLV_KIND_NAMESPACE,
        PAYLOAD_TLV_NAMESPACE_ARG_INDEX,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        sizeof(*snapshot),
        sizeof(*snapshot),
        0,
        0);
}

static __always_inline void emit_namespace_exit_event_v2_direct(
    struct pending_syscall *pending,
    s64 ret_value,
    u64 duration)
{
    struct namespace_snapshot snapshot = {};
    if (ret_value < 0 || !namespace_snapshot_for_exit(pending, &snapshot)) {
        emit_syscall_exit_event_v2_direct(pending, ret_value, duration, 0);
        return;
    }

    u32 payload_size = PAYLOAD_TLV_HEADER_SIZE + NAMESPACE_SNAPSHOT_SIZE;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_size;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    if (!capture_namespace_tlv_direct(&ptr, payload_offset, &snapshot)) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {.seq = sequence};
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
