#ifndef STRACE_GO_SYSCALL_PATH_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PATH_DIRECT_EVENT_V2_H

#include "syscall_path_capture_direct_event_v2.h"

static __always_inline int is_path_only_arg0_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ACCESS || sys_id == SYS_CHDIR || sys_id == SYS_CHROOT ||
        sys_id == SYS_CHMOD || sys_id == SYS_CHOWN || sys_id == SYS_LCHOWN ||
        sys_id == SYS_MKDIR || sys_id == SYS_MKNOD || sys_id == SYS_RMDIR ||
        sys_id == SYS_UNLINK || sys_id == SYS_SWAPON || sys_id == SYS_SWAPOFF ||
        sys_id == SYS_ACCT || sys_id == SYS_TRUNCATE || sys_id == SYS_FSOPEN;
}

static __always_inline int is_path_only_arg1_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_MKDIRAT || sys_id == SYS_MKNODAT || sys_id == SYS_FCHOWNAT ||
        sys_id == SYS_UNLINKAT || sys_id == SYS_FCHMODAT || sys_id == SYS_FACCESSAT ||
        sys_id == SYS_FACCESSAT2 || sys_id == SYS_FSPICK || sys_id == SYS_OPEN_TREE ||
        sys_id == SYS_FILE_GETATTR;
}

static __always_inline int is_path_only_direct_syscall(u32 sys_id)
{
    return is_path_only_arg0_direct_syscall(sys_id) ||
        is_path_only_arg1_direct_syscall(sys_id);
}

static __always_inline int is_dual_path_0_1_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RENAME || sys_id == SYS_LINK || sys_id == SYS_SYMLINK;
}

static __always_inline int is_dual_path_0_2_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SYMLINKAT;
}

static __always_inline int is_dual_path_1_3_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RENAMEAT || sys_id == SYS_RENAMEAT2 || sys_id == SYS_LINKAT;
}

static __always_inline int is_dual_path_direct_syscall(u32 sys_id)
{
    return is_dual_path_0_1_direct_syscall(sys_id) ||
        is_dual_path_0_2_direct_syscall(sys_id) ||
        is_dual_path_1_3_direct_syscall(sys_id);
}

#include "syscall_path_capture_direct_event_v2.h"
#include "syscall_path_emit_direct_event_v2.h"

#endif
