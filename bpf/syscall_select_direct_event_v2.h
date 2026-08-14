#ifndef STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SELECT_DIRECT_EVENT_V2_H

#define SELECT_DIRECT_FDSET_SIZE 128
#define SELECT_DIRECT_TIMEVAL_SIZE 16
#define SELECT_DIRECT_FDSET_ARG_BASE 1
#define SELECT_DIRECT_FDSET_ARG_LAST 3
#define SELECT_DIRECT_CAPTURE_FDSETS 1
#define SELECT_DIRECT_CAPTURE_TIMEOUT 2
#define SELECT_DIRECT_PAYLOAD_MAX \
    (3 * (PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_FDSET_SIZE) + \
     PAYLOAD_TLV_HEADER_SIZE + SELECT_DIRECT_TIMEVAL_SIZE)

static __always_inline int is_select_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SELECT;
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
