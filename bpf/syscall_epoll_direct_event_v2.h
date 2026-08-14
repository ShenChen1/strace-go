#ifndef STRACE_GO_SYSCALL_EPOLL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_EPOLL_DIRECT_EVENT_V2_H

#define EPOLL_DIRECT_EVENT_SIZE 12
#define EPOLL_DIRECT_TIMEOUT_SIZE 16
#define EPOLL_DIRECT_EVENTS_MAX 504
#define EPOLL_DIRECT_EVENT_SLOT_MAX 42

static __always_inline int is_epoll_pwait2_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_PWAIT2;
}

static __always_inline int is_epoll_ctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_CTL;
}

static __always_inline int is_epoll_wait_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_EPOLL_WAIT || sys_id == SYS_EPOLL_PWAIT ||
        is_epoll_pwait2_direct_syscall(sys_id);
}

static __always_inline int is_epoll_direct_syscall(u32 sys_id)
{
    return is_epoll_ctl_direct_syscall(sys_id) ||
        is_epoll_wait_direct_syscall(sys_id);
}

static __always_inline u32 epoll_events_user_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > 0x15555555LL) {
        return 0xffffffffU;
    }
    return (u32)count * EPOLL_DIRECT_EVENT_SIZE;
}

static __always_inline u32 epoll_events_copy_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > EPOLL_DIRECT_EVENT_SLOT_MAX) {
        return EPOLL_DIRECT_EVENTS_MAX;
    }
    return (u32)count * EPOLL_DIRECT_EVENT_SIZE;
}

#include "syscall_epoll_capture_direct_event_v2.h"
#include "syscall_epoll_emit_direct_event_v2.h"

#endif
