#ifndef STRACE_GO_PENDING_STATE_H
#define STRACE_GO_PENDING_STATE_H

// IMPACT: pre-exec child syscalls are intentionally suppressed on both raw
// syscall edges, so their exits cannot be mistaken for attach or map loss.
static __always_inline int is_pre_exec_suppressed_syscall(
    u32 *filter_flags,
    u32 sys_id)
{
    return filter_flags && (*filter_flags & FILTER_TASK_PRE_EXEC) &&
        !is_exec_payload_direct_syscall(sys_id);
}

static __always_inline int is_exec_restart_return(s64 ret_value)
{
    return ret_value == -512 || ret_value == -513 ||
        ret_value == -514 || ret_value == -516;
}

// These raw exits have no independent pending event: lifecycle cleanup owns
// terminating calls, child tasks return from creation calls without an enter,
// and exec restart markers are kernel control flow.
static __always_inline int is_expected_unmatched_exit(u32 sys_id, s64 ret_value)
{
    if (is_terminating_direct_syscall(sys_id)) {
        return 1;
    }
    if (is_process_creation_direct_syscall(sys_id) && ret_value == 0) {
        return 1;
    }
    // sched_process_exec emits and consumes the successful exec completion;
    // the later raw sys_exit edge has no independent pending state.
    if (is_exec_payload_direct_syscall(sys_id) && ret_value == 0) {
        return 1;
    }
    return is_exec_payload_direct_syscall(sys_id) &&
        is_exec_restart_return(ret_value);
}

static __always_inline void record_unmatched_exit_if_needed(u32 pid, u32 tid, u32 sys_id, s64 ret_value)
{
    if (!is_lifecycle_task_tracked(pid, tid)) return;

    // sched_process_exit can race the final raw syscall exit. Once lifecycle
    // has recorded the attach exit fact, classify that late edge as teardown.
    u32 *attach_exited = bpf_map_lookup_elem(&attach_exited_map, &tid);
    if (attach_exited && *attach_exited != 0) return;

    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)) {
        return;
    }
    if (is_expected_unmatched_exit(sys_id, ret_value)) return;
    record_orphan_exit(pid, tid, sys_id, ret_value, ORPHAN_REASON_NO_PENDING);
}

// IMPACT: normal exits use task-local state; only a successful non-leader exec
// may use the process-scoped handoff because Linux changes the task identity.
static __always_inline struct pending_syscall *lookup_pending_syscall_for_exit(
    u32 pid,
    u32 tid,
    s64 ret_value,
    u32 *pending_tid,
    u32 *pending_exec_lookup)
{
    *pending_tid = tid;
    *pending_exec_lookup = 0;

    struct pending_task_state *state = current_pending_task_state();
    if (!state || !state->valid) {
        return 0;
    }

    struct pending_syscall *pending = &state->syscall;
    if (pending->tid == tid) {
        return pending;
    }

    if (ret_value == 0 && is_exec_payload_direct_syscall(pending->sys_id)) {
        u32 *exec_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (exec_tid && *exec_tid == pending->tid) {
            *pending_tid = *exec_tid;
            *pending_exec_lookup = 1;
            return pending;
        }
    }

    return pending;
}

static __always_inline int validate_pending_syscall_exit(
    struct pending_syscall *pending,
    u32 sys_id,
    u32 pid,
    u32 pending_tid)
{
    if (pending->sys_id == sys_id && pending->tid == pending_tid) {
        return 1;
    }

    record_pending_mismatch();
    clear_pending_task_state();
    bpf_map_delete_elem(&pending_exec_map, &pid);
    return 0;
}

static __always_inline u64 pending_syscall_duration(struct pending_syscall *p)
{
    if (p->enter_time == 0) return 0;

    u64 exit_time = bpf_ktime_get_ns();
    if (exit_time <= p->enter_time) return 0;
    return exit_time - p->enter_time;
}

static __always_inline void consume_pending_syscall(
    u32 pid,
    u32 pending_tid,
    struct pending_syscall *pending,
    u32 pending_exec_lookup)
{
    u32 pending_sys_id = pending->sys_id;
    u32 pending_pid = pending->pid;
    clear_pending_task_state();
    if (pending_exec_lookup) {
        bpf_map_delete_elem(&pending_exec_map, &pid);
        bpf_map_delete_elem(&main_exited_map, &pid);
    } else if (is_exec_payload_direct_syscall(pending_sys_id) && pending_tid != pending_pid) {
        bpf_map_delete_elem(&pending_exec_map, &pid);
    }
}

#endif
