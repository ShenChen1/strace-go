#ifndef STRACE_GO_ENTER_ROUTER_H
#define STRACE_GO_ENTER_ROUTER_H

/*
 * enter_router.h - compile-time syscall family to enter ProgArray routing.
 *
 * The raw tracepoint entry owns runtime gates and the tail call. This helper
 * owns only the ordered family classification so new capture families do not
 * expand the attached dispatcher.
 */
static __always_inline u32 select_enter_prog_index(u32 sys_id)
{
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
    return index;
}

#endif
