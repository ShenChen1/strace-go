#ifndef STRACE_GO_LIFECYCLE_DISPATCH_H
#define STRACE_GO_LIFECYCLE_DISPATCH_H

/* lifecycle_dispatch.h owns the sched lifecycle tracepoint programs. */

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
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
        u32 val = 1;
        if (bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY) != 0) {
            record_lifecycle_map_update_fail();
        } else if (bpf_map_update_elem(&pre_exec_map, &child_pid, &val, BPF_ANY) != 0) {
            record_lifecycle_map_update_fail();
            bpf_map_delete_elem(&filter_map, &child_pid);
        }
    }

    if (!is_lifecycle_task_tracked(parent_tgid, parent_tid)) return 0;

    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg && (*cfg & CONFIG_FOLLOW_FORKS)) {
        u32 val = 1;
        if (bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY) != 0) {
            record_lifecycle_map_update_fail();
        }
    }
    emit_lifecycle_event(LIFECYCLE_FORK, parent_tgid, parent_tid, parent_tgid, child_pid, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // IMPACT: ctx->pid does not provide a stable TGID/TID pair for all
    // thread-exec paths; use the current task identity like exit/free.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;

    // IMPACT: once any armed child execs, stop arming so post-start forks are
    // governed by follow-forks instead.
    u32 arm_key = 0;
    u32 *arm_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    u32 *pre_exec = bpf_map_lookup_elem(&pre_exec_map, &tid);
    int tracked = is_lifecycle_task_tracked(pid, tid);
    if (tracked) {
        // IMPACT: only an armed child may consume the initial-fork arm;
        // unrelated tracked execs must not clear another target's startup arm.
        if (pre_exec) {
            bpf_map_delete_elem(&pre_exec_map, &tid);
            if (arm_parent && *arm_parent != 0) {
                u32 zero = 0;
                if (bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY) != 0) {
                    record_lifecycle_map_update_fail();
                }
            }
        }
    }

    if (!tracked) return 0;

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
    // IMPACT: sched_process_exit fires in the exiting task's context; read the
    // pid/tgid directly instead of relying on the tracepoint struct layout.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    if (!is_lifecycle_task_tracked(pid, tid)) return 0;

    mark_attach_task_exited(tid);
    clear_lifecycle_task_state(pid, tid);
    int exit_code = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &task->exit_code);
    }
    emit_lifecycle_event(LIFECYCLE_EXIT, pid, tid, exit_code, 0, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int trace_sched_process_free(struct trace_event_raw_sched_process_template *ctx) {
    // sched_process_free's tracepoint pid is task-scoped; use the current
    // task identity so cleanup remains correct for non-leader threads.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    if (!is_lifecycle_task_tracked(pid, tid)) return 0;

    clear_lifecycle_task_state(pid, tid);
    emit_lifecycle_event(LIFECYCLE_FREE, pid, tid, pid, 0, 0);
    return 0;
}

#endif
