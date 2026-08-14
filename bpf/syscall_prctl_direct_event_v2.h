#ifndef STRACE_GO_SYSCALL_PRCTL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PRCTL_DIRECT_EVENT_V2_H

#define PRCTL_DIRECT_NAME_SIZE 16
#define PRCTL_DIRECT_UINT32_SIZE 4
#define PRCTL_OPTION_GET_PDEATHSIG 1
#define PRCTL_OPTION_SET_NAME 15
#define PRCTL_OPTION_GET_NAME 16

static __always_inline int is_prctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PRCTL;
}

static __always_inline int is_prctl_set_name_option(u64 option)
{
    return option == PRCTL_OPTION_SET_NAME;
}

static __always_inline int is_prctl_get_name_option(u64 option)
{
    return option == PRCTL_OPTION_GET_NAME;
}

static __always_inline int is_prctl_uint32_out_option(u64 option)
{
    return option == PRCTL_OPTION_GET_PDEATHSIG || option == 5 ||
        option == 9 || option == 11 || option == 19 ||
        option == 25 || option == 37;
}

#include "syscall_prctl_capture_direct_event_v2.h"
#include "syscall_prctl_emit_direct_event_v2.h"

#endif
