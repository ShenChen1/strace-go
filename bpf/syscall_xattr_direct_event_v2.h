#ifndef STRACE_GO_SYSCALL_XATTR_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_XATTR_DIRECT_EVENT_V2_H

#define XATTR_DIRECT_PATH_MAX 512
#define XATTR_DIRECT_NAME_MAX 256
#define XATTR_DIRECT_VALUE_MAX 256
#define XATTR_DIRECT_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + XATTR_DIRECT_PATH_MAX + XATTR_DIRECT_NAME_MAX + XATTR_DIRECT_VALUE_MAX)

static __always_inline int is_xattr_set_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETXATTR || sys_id == SYS_LSETXATTR ||
        sys_id == SYS_FSETXATTR;
}

static __always_inline int is_xattr_get_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETXATTR || sys_id == SYS_LGETXATTR ||
        sys_id == SYS_FGETXATTR;
}

static __always_inline int is_xattr_list_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_LISTXATTR || sys_id == SYS_LLISTXATTR ||
        sys_id == SYS_FLISTXATTR;
}

static __always_inline int is_xattr_remove_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_REMOVEXATTR || sys_id == SYS_LREMOVEXATTR ||
        sys_id == SYS_FREMOVEXATTR;
}

static __always_inline int is_xattr_direct_syscall(u32 sys_id)
{
    return is_xattr_set_direct_syscall(sys_id) ||
        is_xattr_get_direct_syscall(sys_id) ||
        is_xattr_list_direct_syscall(sys_id) ||
        is_xattr_remove_direct_syscall(sys_id);
}

static __always_inline int xattr_direct_has_path(u32 sys_id)
{
    return sys_id == SYS_SETXATTR || sys_id == SYS_LSETXATTR ||
        sys_id == SYS_GETXATTR || sys_id == SYS_LGETXATTR ||
        sys_id == SYS_LISTXATTR || sys_id == SYS_LLISTXATTR ||
        sys_id == SYS_REMOVEXATTR || sys_id == SYS_LREMOVEXATTR;
}

static __always_inline int xattr_direct_has_name(u32 sys_id)
{
    return is_xattr_set_direct_syscall(sys_id) ||
        is_xattr_get_direct_syscall(sys_id) ||
        is_xattr_remove_direct_syscall(sys_id);
}

#include "syscall_xattr_capture_direct_event_v2.h"
#include "syscall_xattr_emit_direct_event_v2.h"

#endif
