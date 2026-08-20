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
#include "lifecycle_state.h"
#include "lifecycle_dispatch.h"
#define STRACE_GO_CORE_ONLY 1
#include "enter_dispatch.h"
#include "enter_fragment_dispatch.h"
#include "nested_fd_path_dispatch.h"
#include "mmsg_enter_dispatch.h"
#include "exit_dispatch.h"
#include "exit_direct_dispatch.h"
#include "recvmsg_kretprobe_dispatch.h"
#include "quota_dispatch.h"
#include "mount_query_dispatch.h"
#include "mount_path_dispatch.h"

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id == SYS_RT_SIGRETURN || sys_id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);

    if (!is_lifecycle_task_tracked(pid, tid)) return 0;

    if (is_pre_exec_suppressed_syscall(pid, sys_id)) return 0;
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)) return 0;

    bpf_tail_call(ctx, &enter_routes, sys_id);
    emit_enter_dispatch_fallback(ctx, pid, tid, cfg);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 sys_id = (u32)ctx->id;
    s64 ret_value = ctx->ret;
    if (sys_id == SYS_RT_SIGRETURN || sys_id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = (u32)(pid_tgid >> 32);
    if (is_pre_exec_suppressed_syscall(pid, sys_id)) return 0;

    if (!is_lifecycle_task_tracked(pid, tid)) return 0;
    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)) {
        return 0;
    }

    bpf_tail_call(ctx, &exit_routes, sys_id);

    // Tail-call fallback is isolated from the normal handler ownership path.
    emit_exit_dispatch_fallback(pid, tid, sys_id, ret_value);
    return 0;
}
