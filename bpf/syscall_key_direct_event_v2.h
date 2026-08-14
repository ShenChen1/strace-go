#ifndef STRACE_GO_SYSCALL_KEY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_KEY_DIRECT_EVENT_V2_H

#define KEY_DIRECT_TYPE_MAX 64
#define KEY_DIRECT_DESCRIPTION_MAX 128
#define KEY_DIRECT_PAYLOAD_MAX 256
#define KEY_DIRECT_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + KEY_DIRECT_TYPE_MAX + KEY_DIRECT_DESCRIPTION_MAX + KEY_DIRECT_PAYLOAD_MAX)

static __always_inline int is_key_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ADD_KEY || sys_id == SYS_REQUEST_KEY;
}

#include "syscall_key_capture_direct_event_v2.h"
#include "syscall_key_emit_direct_event_v2.h"

#endif
