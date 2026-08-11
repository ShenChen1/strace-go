#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
#include "runtime_abi.h"
#include "runtime_stats.h"
#include "lifecycle_event_v2.h"

#include "syscall_direct_event_v2.h"
#include "syscall_fd_state_direct_event_v2.h"
#include "syscall_fd_array_direct_event_v2.h"
#include "syscall_getcwd_direct_event_v2.h"
#include "syscall_misc_struct_direct_event_v2.h"
#include "syscall_path_stat_direct_event_v2.h"
#include "syscall_path_direct_event_v2.h"
#include "syscall_mount_path_direct_event_v2.h"
#include "syscall_openat2_direct_event_v2.h"
#include "syscall_readlink_direct_event_v2.h"
#include "syscall_small_struct_direct_event_v2.h"
#include "syscall_stat_direct_event_v2.h"
#include "syscall_waitid_direct_event_v2.h"
#include "syscall_signal_direct_event_v2.h"
#include "syscall_cachestat_direct_event_v2.h"
#include "syscall_capability_direct_event_v2.h"
#include "syscall_memfd_direct_event_v2.h"
#include "syscall_prctl_direct_event_v2.h"
#include "syscall_clone3_direct_event_v2.h"
#include "syscall_bpf_direct_event_v2.h"
#include "syscall_iovec_direct_event_v2.h"
#include "syscall_iovec_base_exit_direct_event_v2.h"
#include "syscall_msg_direct_event_v2.h"
#include "syscall_fcntl_direct_event_v2.h"
#include "syscall_ioctl_direct_event_v2.h"
#include "syscall_network_direct_event_v2.h"
#include "syscall_network_direct_exit_event_v2.h"
#include "syscall_key_direct_event_v2.h"
#include "syscall_xattr_direct_event_v2.h"
#include "syscall_fs_direct_event_v2.h"
#include "syscall_aio_getevents_direct_event_v2.h"
#include "syscall_aio_direct_event_v2.h"
#include "syscall_poll_direct_event_v2.h"
#include "syscall_select_direct_event_v2.h"
#include "syscall_epoll_direct_event_v2.h"
#include "syscall_file_time_direct_event_v2.h"
#include "syscall_time_direct_event_v2.h"
#include "syscall_futex_direct_event_v2.h"
#include "syscall_sleep_direct_event_v2.h"
#include "syscall_timex_direct_event_v2.h"
#include "syscall_quota_xfs_direct_event_v2.h"
#include "syscall_quota_direct_event_v2.h"

#include "pending_state.h"
#include "enter_dispatch.h"
#include "mmsg_enter_dispatch.h"
#include "exit_dispatch.h"
#include "quota_dispatch.h"
#include "mount_query_dispatch.h"
#include "mount_path_dispatch.h"

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id == SYS_RT_SIGRETURN || sys_id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;

    if (is_pre_exec_suppressed_syscall(pid, sys_id)) return 0;
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)) return 0;

    u64 enter_time = bpf_ktime_get_ns();

    u32 index = ENTER_PROG_NO_PAYLOAD_DIRECT;
    if (is_terminating_direct_syscall(sys_id)) {
        index = ENTER_PROG_TERMINATING;
    } else if (is_exec_payload_direct_syscall(sys_id)) {
        index = ENTER_PROG_EXEC;
    } else if (is_path_stat_direct_syscall(sys_id)) {
        index = ENTER_PROG_PATH_STAT;
    } else if (is_path_only_direct_syscall(sys_id)) {
        index = ENTER_PROG_PATH_ONLY;
    } else if (is_mount_path_direct_syscall(sys_id)) {
        index = ENTER_PROG_MOUNT_PATH;
    } else if (is_dual_path_direct_syscall(sys_id)) {
        index = ENTER_PROG_DUAL_PATH;
    } else if (is_openat2_direct_syscall(sys_id)) {
        index = ENTER_PROG_OPENAT2;
    } else if (is_readlink_direct_syscall(sys_id)) {
        index = ENTER_PROG_READLINK;
    } else if (is_misc_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_MISC_STRUCT;
    } else if (is_small_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_SMALL_STRUCT;
    } else if (is_itimer_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_ITIMER;
    } else if (is_time_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_TIME_STRUCT;
    } else if (is_signal_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_SIGNAL;
    } else if (is_file_time_direct_syscall(sys_id)) {
        index = ENTER_PROG_FILE_TIME;
    } else if (sys_id == SYS_NANOSLEEP || sys_id == SYS_CLOCK_NANOSLEEP) {
        index = ENTER_PROG_SLEEP;
    } else if (sys_id == SYS_FUTEX || sys_id == SYS_FUTEX_WAIT ||
               sys_id == SYS_FUTEX_WAITV || sys_id == SYS_FUTEX_REQUEUE) {
        index = ENTER_PROG_FUTEX;
    } else if (sys_id == SYS_CACHESTAT) {
        index = ENTER_PROG_CACHESTAT;
    } else if (is_quota_direct_syscall(sys_id)) {
        index = ENTER_PROG_QUOTA;
    } else if (is_capability_direct_syscall(sys_id)) {
        index = ENTER_PROG_CAPABILITY;
    } else if (is_memfd_create_direct_syscall(sys_id)) {
        index = ENTER_PROG_MEMFD;
    } else if (is_prctl_direct_syscall(sys_id)) {
        index = ENTER_PROG_PRCTL;
    } else if (is_clone3_direct_syscall(sys_id)) {
        index = ENTER_PROG_CLONE3;
    } else if (is_bpf_direct_syscall(sys_id)) {
        index = ENTER_PROG_BPF;
    } else if (is_iovec_direct_syscall(sys_id)) {
        index = ENTER_PROG_IOVEC;
    } else if (is_msg_direct_syscall(sys_id)) {
        index = is_single_msg_direct_syscall(sys_id) ? ENTER_PROG_MSG : ENTER_PROG_MMSG;
    } else if (is_fcntl_direct_syscall(sys_id)) {
        index = ENTER_PROG_FCNTL;
    } else if (is_ioctl_direct_syscall(sys_id)) {
        index = ENTER_PROG_IOCTL;
    } else if (is_network_direct_syscall(sys_id)) {
        index = ENTER_PROG_NETWORK;
    } else if (is_key_direct_syscall(sys_id)) {
        index = ENTER_PROG_KEY;
    } else if (is_xattr_direct_syscall(sys_id)) {
        index = ENTER_PROG_XATTR;
    } else if (is_fs_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_FS;
    } else if (is_aio_direct_syscall(sys_id)) {
        index = ENTER_PROG_AIO;
    } else if (is_poll_direct_syscall(sys_id)) {
        index = ENTER_PROG_POLL;
    } else if (is_select_direct_syscall(sys_id)) {
        index = ENTER_PROG_SELECT;
    } else if (is_epoll_ctl_direct_syscall(sys_id) || is_epoll_pwait2_direct_syscall(sys_id)) {
        index = ENTER_PROG_EPOLL;
    } else if (is_scalar_direct_syscall(sys_id) || is_exit_payload_direct_syscall(sys_id) ||
               is_fd_array_direct_syscall(sys_id) || is_getcwd_direct_syscall(sys_id) ||
               is_time_struct_direct_syscall(sys_id) || is_stat_struct_direct_syscall(sys_id) ||
               is_waitid_direct_syscall(sys_id) ||
               is_misc_struct_direct_syscall(sys_id) || is_small_struct_direct_syscall(sys_id)) {
        index = ENTER_PROG_NO_PAYLOAD_DIRECT;
    } else if (is_payload_direct_syscall(sys_id)) {
        index = ENTER_PROG_PAYLOAD_DIRECT;
    }

    bpf_tail_call(ctx, &enter_progs, index);

    // tail call fallback: keep the syscall observable even if a handler slot is missing.
    volatile s32 stack_id = -1;
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id == SYS_RT_SIGRETURN || ctx->id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_pre_exec_suppressed_syscall(pid, (u32)ctx->id)) return 0;

    u32 pending_tid = tid;
    u32 pending_exec_lookup = 0;
    struct pending_syscall *p = lookup_pending_syscall_for_exit(
        pid,
        tid,
        ctx->ret,
        &pending_tid,
        &pending_exec_lookup);
    if (!p) {
        if (!is_lifecycle_task_tracked(pid, tid)) return 0;
        u32 cfg_key = 0;
        u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
        if (!should_trace_syscall((u32)ctx->id, cfg) &&
            !is_fd_state_tracked((u32)ctx->id, cfg)) {
            return 0;
        }
        record_orphan_exit();
        return 0;
    }
    if (!validate_pending_syscall_exit(
            p,
            (u32)ctx->id,
            pid,
            pending_tid)) {
        return 0;
    }

    u32 index = EXIT_PROG_GENERIC;
    if (is_quota_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_QUOTA;
    } else if (is_mount_query_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_MOUNT_QUERY;
    } else if (is_iovec_base_exit_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_IOVEC_BASE;
    } else if (is_single_msg_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_MSG;
    } else if (is_mmsg_direct_syscall(p->sys_id)) {
        index = (p->sys_id == SYS_RECVMMSG) ? EXIT_PROG_RECVMMSG_BASE0 : EXIT_PROG_MMSG_FINAL;
    }
    bpf_tail_call(ctx, &exit_progs, index);

    // tail call fallback: emit a minimal no-payload exit and consume pending.
    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }
    emit_syscall_exit_event_v2_direct(p, ctx->ret, duration, 0);
    consume_pending_syscall(pid, pending_tid, p, pending_exec_lookup);
    return 0;
}


// IMPACT: one kretprobe dispatcher serializes all recvmsg OUT fragments on the
// same return path; each tail target remains small enough for the verifier.
SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_dispatch(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p || p->sys_id != SYS_RECVMSG) return 0;

    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_NAME);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_name(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmsg_name_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_CONTROL);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_control(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmsg_control_exit_fragment_event_v2_direct(p, ret_value, duration);
    bpf_tail_call(ctx, &recvmsg_progs, RECVMSG_PROG_FINAL);
    return 0;
}

SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_final(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p || p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_single_msg_exit_event_v2_direct(p, ret_value, duration);
    consume_pending_syscall(pid, tid, p, 0);
    return 0;
}


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
        bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);
        bpf_map_update_elem(&pre_exec_map, &child_pid, &val, BPF_ANY);
    }

    if (!is_lifecycle_task_tracked(parent_tgid, parent_tid)) return 0;
    
    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg && (*cfg & CONFIG_FOLLOW_FORKS)) {
        u32 val = 1;
        bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);
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
                bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY);
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
