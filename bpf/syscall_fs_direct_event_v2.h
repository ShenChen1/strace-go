#ifndef STRACE_GO_SYSCALL_FS_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FS_DIRECT_EVENT_V2_H

#include "syscall_mount_setattr_direct_event_v2.h"
#include "syscall_mount_query_direct_event_v2.h"

#define FS_DIRECT_MOUNT_STRING_MAX 512
#define FS_DIRECT_MOUNT_TYPE_MAX 128
#define FS_DIRECT_FSCONFIG_KEY_MAX 257
#define FS_DIRECT_FSCONFIG_VALUE_MAX 4096
#define FS_DIRECT_FSCONFIG_SET_BINARY 2
#define FS_DIRECT_FSCONFIG_VALUE_LEN_MASK 8191
#define FS_DIRECT_GETDENTS_BYTES_MAX 512
#define FS_DIRECT_PAYLOAD_CAPACITY MOUNT_SETATTR_DIRECT_PAYLOAD_CAPACITY

static __always_inline int is_fs_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_MOUNT || sys_id == SYS_UMOUNT2 ||
        sys_id == SYS_FSCONFIG || sys_id == SYS_MOUNT_SETATTR ||
        is_mount_query_direct_syscall(sys_id);
}

static __always_inline int is_getdents_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETDENTS || sys_id == SYS_GETDENTS64;
}

static __always_inline int is_fs_direct_syscall(u32 sys_id)
{
    return is_fs_enter_direct_syscall(sys_id) ||
        is_getdents_direct_syscall(sys_id);
}

#include "syscall_fs_capture_direct_event_v2.h"
#include "syscall_fs_emit_direct_event_v2.h"

#endif
