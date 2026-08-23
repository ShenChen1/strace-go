#ifndef STRACE_GO_LIFECYCLE_DISPATCH_H
#define STRACE_GO_LIFECYCLE_DISPATCH_H

/* lifecycle_dispatch.h owns the sched lifecycle tracepoint programs. */

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    record_lifecycle_fork_seen();
    u32 child_pid = ctx->child_pid;
    // IMPACT: the tracepoint exposes only child TID. Keep the parent's TGID
    // and actual forking TID in the lifecycle envelope; Go resolves the child
    // TGID when the first child task event arrives.
    u64 parent_pid_tgid = bpf_get_current_pid_tgid();
    u32 parent_tgid = (u32)(parent_pid_tgid >> 32);
    u32 parent_tid = (u32)parent_pid_tgid;

    // IMPACT: when strace-go arms the next fork, the tracee's pid filter is
    // installed at fork time so its initial execve (which happens before
    // cmd.Start() returns) is captured like upstream strace does. os/exec may
    // fork several children from the armed parent, so keep the arm on the
    // parent until one of its children execs.
    u32 arm_key = 0;
    u32 *arm_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    if (arm_parent && *arm_parent != 0 && *arm_parent == parent_tgid) {
        install_pre_exec_filter(child_pid);
    }

    if (!is_lifecycle_task_tracked(parent_tgid, parent_tid)) {
        record_lifecycle_fork_parent_untracked();
        return 0;
    }
    record_lifecycle_fork_parent_tracked();

    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg && (*cfg & CONFIG_FOLLOW_FORKS)) {
        record_lifecycle_fork_child_filter(install_tracked_filter(child_pid));
    }
    emit_lifecycle_event(LIFECYCLE_FORK, parent_tgid, parent_tid, parent_tgid, child_pid, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    record_lifecycle_exec_seen();
    // IMPACT: ctx->pid does not provide a stable TGID/TID pair for all
    // thread-exec paths; use the current task identity like exit/free.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;

    // IMPACT: once any armed child execs, stop arming so post-start forks are
    // governed by follow-forks instead.
    u32 arm_key = 0;
    u32 *arm_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    int tracked = is_lifecycle_task_tracked(pid, tid);
    if (tracked) {
        // IMPACT: only an armed child may consume the initial-fork arm;
        // unrelated tracked execs must not clear another target's startup arm.
        int pre_exec_owner = clear_pre_exec_filter(tid);
        if (pre_exec_owner) {
            if (arm_parent && *arm_parent != 0) {
                u32 zero = 0;
                if (bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0) {
                    record_lifecycle_map_update_fail();
                }
            }
        }
    }

    if (!tracked) {
        record_lifecycle_exec_untracked();
        return 0;
    }

    u32 filename_offset = ctx->__data_loc_filename & 0xffff;
    void *filename = 0;
    if (filename_offset > 0) {
        filename = (void *)((char *)ctx + filename_offset);
    }
    emit_lifecycle_event(LIFECYCLE_EXEC, pid, tid, ctx->old_pid, tid, filename);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    record_lifecycle_exit_seen();
    // IMPACT: sched_process_exit fires in the exiting task's context; read the
    // pid/tgid directly instead of relying on the tracepoint struct layout.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    if (!is_lifecycle_task_tracked(pid, tid)) {
        record_lifecycle_exit_untracked();
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_exec_replaced_leader(task, pid, tid)) {
        clear_replaced_leader_task_state(tid);
        return 0;
    }

    mark_attach_task_exited(tid);
    clear_lifecycle_task_state(pid, tid);
    int exit_code = 0;
    if (task) {
        bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &task->exit_code);
    }
    emit_lifecycle_event(LIFECYCLE_EXIT, pid, tid, exit_code, 0, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int trace_sched_process_free(struct trace_event_raw_sched_process_template *ctx) {
    // The raw sched_process_free template carries the freed task PID, while
    // The current-task helper may identify the scheduler context instead.
    // Use the tracepoint PID for task-scoped cleanup so a child free cannot
    // delete the tracked filter of an unrelated live process.
    u32 tid = (u32)ctx->pid;
    if (tid == 0 || !is_lifecycle_task_tracked(tid, tid)) return 0;

    clear_lifecycle_task_state(tid, tid);
    emit_lifecycle_event(LIFECYCLE_FREE, tid, tid, tid, 0, 0);
    return 0;
}

#endif
