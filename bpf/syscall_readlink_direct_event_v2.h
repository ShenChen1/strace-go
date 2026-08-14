#ifndef STRACE_GO_SYSCALL_READLINK_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_READLINK_DIRECT_EVENT_V2_H

#define READLINK_DIRECT_PATH_MAX 512
#define READLINK_DIRECT_BYTES_MAX 512

static __always_inline int is_readlink_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_READLINK || sys_id == SYS_READLINKAT;
}

static __always_inline u16 readlink_direct_buf_arg_index(u32 sys_id)
{
    if (sys_id == SYS_READLINKAT) {
        return 2;
    }
    return 1;
}

static __always_inline u64 readlink_direct_buf_user_ptr(struct pending_syscall *p)
{
    if (p->sys_id == SYS_READLINKAT) {
        return p->args[2];
    }
    return p->args[1];
}

#include "syscall_readlink_capture_direct_event_v2.h"
#include "syscall_readlink_emit_direct_event_v2.h"

#endif
