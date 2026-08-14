#ifndef STRACE_GO_SYSCALL_FD_PATH_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_PATH_DIRECT_EVENT_V2_H

#define FD_PATH_DIRECT_MAX 512
#define FD_PATH_DIRECT_MAX_ARGS 2
#define FD_PATH_AT_FDCWD (-100)
#define FD_PATH_STATE_PREFIX_SIZE 48
#define FD_PATH_DENTRY_MAX 8
#define FD_PATH_PROBE_PATH_FAILED (-36)
#define FD_PATH_DIRECT_SECTION_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + FD_PATH_STATE_PREFIX_SIZE + FD_PATH_DIRECT_MAX)

static __always_inline u32 fd_path_arg_mask(u32 sys_id)
{
    switch (sys_id) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_PREAD64:
    case SYS_PWRITE64:
    case SYS_READV:
    case SYS_WRITEV:
    case SYS_PREADV:
    case SYS_PWRITEV:
    case SYS_PREADV2:
    case SYS_PWRITEV2:
    case SYS_CLOSE:
    case SYS_FSTAT:
    case SYS_FCHDIR:
    case SYS_FSTATFS:
    case SYS_FCNTL:
    case SYS_EPOLL_WAIT:
    case SYS_EPOLL_PWAIT:
    case SYS_EPOLL_PWAIT2:
    case SYS_CACHESTAT:
    case SYS_OPEN_TREE:
    case SYS_FSPICK:
        return 1U << 0;
    case SYS_DUP2:
    case SYS_DUP3:
        return (1U << 0) | (1U << 1);
    case SYS_EPOLL_CTL:
        return (1U << 0) | (1U << 2);
    case SYS_OPENAT:
    case SYS_OPENAT2:
    case SYS_FCHOWNAT:
    case SYS_FUTIMESAT:
    case SYS_NEWFSTATAT:
    case SYS_UNLINKAT:
    case SYS_RENAMEAT:
    case SYS_LINKAT:
    case SYS_SYMLINKAT:
    case SYS_READLINKAT:
    case SYS_FCHMODAT:
    case SYS_FACCESSAT:
    case SYS_MKDIRAT:
    case SYS_FACCESSAT2:
        return 1U << 0;
    case SYS_DUP:
        return 1U << 0;
    default:
        return 0;
    }
}

static __always_inline u32 fd_path_arg_count(u32 sys_id)
{
    u32 mask = fd_path_arg_mask(sys_id);
    u32 count = 0;
    for (u32 i = 0; i < 6; i++) {
        if (mask & (1U << i)) {
            count++;
        }
    }
    if (count > FD_PATH_DIRECT_MAX_ARGS) {
        return FD_PATH_DIRECT_MAX_ARGS;
    }
    return count;
}

static __always_inline u32 fd_path_payload_capacity(u32 sys_id)
{
    return fd_path_arg_count(sys_id) * FD_PATH_DIRECT_SECTION_MAX;
}

#include "syscall_fd_path_capture_direct_event_v2.h"
#include "syscall_fd_path_emit_direct_event_v2.h"

#endif
