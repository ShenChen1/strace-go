#ifndef STRACE_GO_SYSCALL_SMALL_STRUCT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SMALL_STRUCT_DIRECT_EVENT_V2_H

#define SMALL_STRUCT_DIRECT_WORD_SIZE 8
#define SMALL_STRUCT_DIRECT_MAX_SECTIONS 2
#define SMALL_STRUCT_DIRECT_MAX_PAYLOAD \
    (SMALL_STRUCT_DIRECT_MAX_SECTIONS * (PAYLOAD_TLV_HEADER_SIZE + SMALL_STRUCT_DIRECT_WORD_SIZE))

static __always_inline int is_arch_prctl_get_direct_option(u64 option)
{
    return option == 0x1003 || option == 0x1004 || option == 0x1011 ||
        option == 0x1021 || option == 0x1022 || option == 0x1024;
}

static __always_inline int is_small_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||
        sys_id == SYS_GET_ROBUST_LIST || sys_id == SYS_COPY_FILE_RANGE;
}

static __always_inline int is_small_struct_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_COPY_FILE_RANGE;
}

static __always_inline int is_small_struct_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDFILE || sys_id == SYS_ARCH_PRCTL ||
        sys_id == SYS_GET_ROBUST_LIST;
}

#include "syscall_small_struct_capture_direct_event_v2.h"
#include "syscall_small_struct_emit_direct_event_v2.h"

#endif
