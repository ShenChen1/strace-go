#ifndef STRACE_GO_HANDLER_COMMON_H
#define STRACE_GO_HANDLER_COMMON_H

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
#include "syscall_namespace_direct_event_v2.h"

#endif
