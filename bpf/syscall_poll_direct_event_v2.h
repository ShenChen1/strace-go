#ifndef STRACE_GO_SYSCALL_POLL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_POLL_DIRECT_EVENT_V2_H

#define POLL_DIRECT_FD_SIZE 8
#define POLL_DIRECT_FDS_MAX 512
#define POLL_DIRECT_FD_SLOT_MAX 64
#define POLL_DIRECT_TIMEOUT_SIZE 16
#define POLL_DIRECT_SIGMASK_SIZE 8

static __always_inline int is_poll_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_POLL || sys_id == SYS_PPOLL;
}

static __always_inline int is_ppoll_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PPOLL;
}

static __always_inline u64 poll_direct_count(u32 sys_id, u64 raw_count)
{
    if (is_ppoll_direct_syscall(sys_id)) {
        return (u32)raw_count;
    }
    return raw_count;
}

static __always_inline u32 poll_fds_user_len(u64 count)
{
    if (count > 0x1fffffffULL) {
        return 0xffffffffU;
    }
    return (u32)count * POLL_DIRECT_FD_SIZE;
}

static __always_inline u32 poll_fds_copy_len(u64 count)
{
    if (count > POLL_DIRECT_FD_SLOT_MAX) {
        return POLL_DIRECT_FDS_MAX;
    }
    return (u32)count * POLL_DIRECT_FD_SIZE;
}

#include "syscall_poll_capture_direct_event_v2.h"
#include "syscall_poll_emit_direct_event_v2.h"

#endif
