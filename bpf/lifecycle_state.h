#ifndef STRACE_GO_LIFECYCLE_STATE_H
#define STRACE_GO_LIFECYCLE_STATE_H

/* lifecycle_state.h owns process/TID-scoped cleanup for lifecycle events. */

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

static __always_inline void clear_process_lifecycle_state(u32 pid)
{
    bpf_map_delete_elem(&filter_map, &pid);
    bpf_map_delete_elem(&attach_roots_map, &pid);
    bpf_map_delete_elem(&pending_exec_map, &pid);
    bpf_map_delete_elem(&main_exited_map, &pid);
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
    bpf_map_delete_elem(&pending_syscalls, &tid);
    bpf_map_delete_elem(&pre_exec_map, &tid);
}

// Lifecycle cleanup is split by ownership: pending state is TID-scoped, while
// exec/main/filter state is process-scoped unless a child thread owns it.
static __always_inline void clear_lifecycle_task_state(u32 pid, u32 tid)
{
    bpf_map_delete_elem(&pending_syscalls, &tid);
    bpf_map_delete_elem(&pre_exec_map, &tid);

    if (tid != pid) {
        u32 *pending_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (pending_tid && *pending_tid == tid) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
        }
        bpf_map_delete_elem(&filter_map, &tid);
        bpf_map_delete_elem(&attach_roots_map, &tid);
        return;
    }

    clear_process_lifecycle_state(pid);
}

#endif
