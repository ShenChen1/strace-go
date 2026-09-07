#ifndef STRACE_GO_LIFECYCLE_STATE_H
#define STRACE_GO_LIFECYCLE_STATE_H

/* lifecycle_state.h owns process/TID-scoped cleanup for lifecycle events. */

#define CLONE_PTRACE_FLAG 0x00002000
#define CLONE_PARENT_FLAG 0x00008000

static __always_inline void capture_pending_fork_flags(
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx)
{
    u64 flags = 0;
    if (sys_id == SYS_CLONE) {
        flags = ctx->args[0];
    } else if (sys_id == SYS_CLONE3) {
        void *clone_args = (void *)ctx->args[0];
        if (!clone_args || bpf_probe_read_user(&flags, sizeof(flags), clone_args) != 0) {
            return;
        }
    } else {
        return;
    }
    if (bpf_map_update_elem(&pending_fork_flags_map, &tid, &flags, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
    }
}

static __always_inline u64 pending_fork_flags(u32 tid)
{
    u64 *flags = bpf_map_lookup_elem(&pending_fork_flags_map, &tid);
    return flags ? *flags : 0;
}

static __always_inline void clear_pending_fork_flags(u32 tid, u32 sys_id)
{
    if (sys_id == SYS_CLONE || sys_id == SYS_CLONE3) {
        bpf_map_delete_elem(&pending_fork_flags_map, &tid);
    }
}

static __always_inline void mark_unknown_child(u32 tid, u32 parent_tgid)
{
    if (bpf_map_update_elem(&unknown_children_map, &tid, &parent_tgid, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
    }
}

static __always_inline u32 take_unknown_child(u32 tid)
{
    u32 *parent_tgid = bpf_map_lookup_elem(&unknown_children_map, &tid);
    if (!parent_tgid) return 0;
    u32 parent = *parent_tgid;
    bpf_map_delete_elem(&unknown_children_map, &tid);
    return parent;
}

static __always_inline void clear_armed_fork_parent(u32 pid)
{
    u32 arm_key = 0;
    u32 *armed_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    if (!armed_parent || *armed_parent != pid) {
        return;
    }

    u32 zero = 0;
    if (bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
    }
}

static __always_inline int install_pre_exec_filter(u32 tid)
{
    u32 value = FILTER_TASK_TRACKED | FILTER_TASK_PRE_EXEC;
    if (bpf_map_update_elem(&filter_map, &tid, &value, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
        return 0;
    }
    return 1;
}

static __always_inline int install_tracked_filter(u32 tid)
{
    u32 value = FILTER_TASK_TRACKED;
    u32 *existing = bpf_map_lookup_elem(&filter_map, &tid);
    if (existing) {
        value |= *existing & FILTER_TASK_PRE_EXEC;
    }
    if (bpf_map_update_elem(&filter_map, &tid, &value, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
        return 0;
    }
    return 1;
}

static __always_inline int clear_pre_exec_filter(u32 tid)
{
    u32 *flags = bpf_map_lookup_elem(&filter_map, &tid);
    if (!flags || !(*flags & FILTER_TASK_PRE_EXEC)) {
        return 0;
    }

    u32 value = *flags & ~FILTER_TASK_PRE_EXEC;
    if (bpf_map_update_elem(&filter_map, &tid, &value, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
        return 0;
    }
    return 1;
}

static __always_inline int adopt_exec_task_tracking(
    u32 pid,
    u32 tid,
    u32 old_tid)
{
    if (is_lifecycle_task_tracked(pid, tid)) return 1;
    if (old_tid == 0 || old_tid == tid) return 0;

    u32 *old_flags = bpf_map_lookup_elem(&filter_map, &old_tid);
    if (!old_flags) return 0;
    u32 value = *old_flags;
    if (!(value & FILTER_TASK_TRACKED)) return 0;
    if (bpf_map_update_elem(&filter_map, &pid, &value, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
        return 0;
    }
    bpf_map_delete_elem(&filter_map, &old_tid);
    return 1;
}

static __always_inline void clear_process_lifecycle_state(u32 pid)
{
    bpf_map_delete_elem(&filter_map, &pid);
    bpf_map_delete_elem(&attach_roots_map, &pid);
    bpf_map_delete_elem(&pending_exec_map, &pid);
    bpf_map_delete_elem(&main_exited_map, &pid);
    bpf_map_delete_elem(&pending_fork_flags_map, &pid);
    bpf_map_delete_elem(&unknown_children_map, &pid);
    clear_armed_fork_parent(pid);
}

// A successful non-leader exec first exits the old group leader. Preserve the
// process-scoped filter until group_exec_task becomes the new leader.
static __always_inline int is_exec_replaced_leader(
    struct task_struct *task,
    u32 pid,
    u32 tid)
{
    if (!task || tid != pid) return 0;

    u32 *pending_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
    if (!pending_tid || *pending_tid == pid) return 0;
    u32 expected_tid = *pending_tid;

    struct task_struct *exec_task = BPF_CORE_READ(task, signal, group_exec_task);
    if (!exec_task) return 0;

    u32 exec_tid = BPF_CORE_READ(exec_task, pid);
    return exec_tid == expected_tid;
}

static __always_inline void clear_replaced_leader_task_state(u32 tid)
{
    clear_pending_task_state();
}

// Lifecycle cleanup is split by ownership: pending state is TID-scoped, while
// exec/main/filter state is process-scoped unless a child thread owns it.
static __always_inline void clear_lifecycle_task_state(u32 pid, u32 tid)
{
    clear_pending_task_state();

    if (tid != pid) {
        u32 *pending_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (pending_tid && *pending_tid == tid) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
        }
        bpf_map_delete_elem(&filter_map, &tid);
        bpf_map_delete_elem(&attach_roots_map, &tid);
        bpf_map_delete_elem(&pending_fork_flags_map, &tid);
        bpf_map_delete_elem(&unknown_children_map, &tid);
        return;
    }

    clear_process_lifecycle_state(pid);
}

#endif
