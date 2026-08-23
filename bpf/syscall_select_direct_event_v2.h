#ifndef STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H

#define SELECT_DIRECT_FDSET_SIZE 128
#define SELECT_DIRECT_TIMEVAL_SIZE 16
#define SELECT_DIRECT_TIMESPEC_SIZE 16
#define SELECT_DIRECT_PSELECT6_WRAPPER_SIZE 16
#define SELECT_DIRECT_PSELECT6_SIGMASK_SIZE 8
#define SELECT_DIRECT_PSELECT6_SIGMASK_ARG_INDEX 6
#define SELECT_DIRECT_FDSET_ARG_BASE 1
#define SELECT_DIRECT_FDSET_ARG_LAST 3
#define SELECT_DIRECT_CAPTURE_FDSETS 1
#define SELECT_DIRECT_CAPTURE_TIMEOUT 2
#define SELECT_DIRECT_CAPTURE_SIGMASK 4
#define SELECT_DIRECT_FD_PATH_MAX FD_PATH_NESTED_MAX
#define SELECT_DIRECT_BASE_PAYLOAD_MAX \
    (3 * (PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_FDSET_SIZE) + \
     PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_TIMEVAL_SIZE)
#define SELECT_DIRECT_PSELECT6_PAYLOAD_MAX \
    (SELECT_DIRECT_BASE_PAYLOAD_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_PSELECT6_WRAPPER_SIZE + \
     PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_PSELECT6_SIGMASK_SIZE)
#define SELECT_DIRECT_PAYLOAD_MAX SELECT_DIRECT_PSELECT6_PAYLOAD_MAX

static __always_inline int is_select_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SELECT || sys_id == SYS_PSELECT6;
}

static __always_inline int is_pselect6_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PSELECT6;
}

static __always_inline u32 select_direct_payload_capacity(u32 sys_id)
{
    if (is_pselect6_direct_syscall(sys_id)) {
        return SELECT_DIRECT_PSELECT6_PAYLOAD_MAX;
    }
    return SELECT_DIRECT_BASE_PAYLOAD_MAX;
}

static __always_inline u32 select_direct_fdset_user_len(u64 nfds_raw)
{
    s32 nfds = (s32)nfds_raw;
    if (nfds <= 0) {
        return 0;
    }
    if (nfds > SELECT_DIRECT_FDSET_SIZE * 8) {
        return SELECT_DIRECT_FDSET_SIZE;
    }
    return (u32)((nfds + 7) / 8);
}

#include "syscall_select_capture_direct_event_v2.h"
#include "syscall_select_emit_direct_event_v2.h"

#endif
