#ifndef STRACE_GO_EXIT_ROUTER_H
#define STRACE_GO_EXIT_ROUTER_H

/*
 * exit_router.h - raw syscall id to exit ProgArray routing.
 *
 * The raw exit entry owns runtime gates and the tail call. This helper owns
 * only the ordered family classification used by that tail call.
 */
static __always_inline u32 select_exit_prog_index(u32 sys_id)
{
    u32 index = EXIT_PROG_GENERIC;
    if (is_path_only_direct_syscall(sys_id) ||
        is_dual_path_direct_syscall(sys_id) ||
        is_open_creat_path_direct_syscall(sys_id) ||
        is_openat2_direct_syscall(sys_id)) {
        index = EXIT_PROG_PATH;
    } else if (is_quota_direct_syscall(sys_id)) {
        index = EXIT_PROG_QUOTA;
    } else if (is_mount_query_direct_syscall(sys_id)) {
        index = EXIT_PROG_MOUNT_QUERY;
    } else if (is_iovec_base_exit_direct_syscall(sys_id)) {
        index = EXIT_PROG_IOVEC_BASE;
    } else if (is_single_msg_direct_syscall(sys_id)) {
        index = EXIT_PROG_MSG;
    } else if (is_mmsg_direct_syscall(sys_id)) {
        index = (sys_id == SYS_RECVMMSG) ? EXIT_PROG_RECVMMSG_BASE01 : EXIT_PROG_MMSG_FINAL;
    }
    return index;
}

#endif
