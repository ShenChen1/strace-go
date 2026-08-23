#ifndef STRACE_GO_SYSCALL_KEY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_KEY_DIRECT_EVENT_V2_H

#define KEY_DIRECT_TYPE_MAX 64
#define KEY_DIRECT_DESCRIPTION_MAX 128
#define KEY_DIRECT_PAYLOAD_MAX 256
#define KEY_DIRECT_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + KEY_DIRECT_TYPE_MAX + KEY_DIRECT_DESCRIPTION_MAX + KEY_DIRECT_PAYLOAD_MAX)
#define KEYCTL_DIRECT_PAYLOAD_CAPACITY \
    (2 * (PAYLOAD_TLV_HEADER_SIZE + KEY_DIRECT_PAYLOAD_MAX))

#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_UPDATE 2
#define KEYCTL_DESCRIBE 6
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12
#define KEYCTL_REJECT 19
#define KEYCTL_GET_SECURITY 17
#define KEYCTL_CAPABILITIES 31
#endif

static __always_inline int is_keyctl_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_KEYCTL;
}

static __always_inline int is_keyctl_output_operation(u64 operation)
{
    return operation == KEYCTL_DESCRIBE || operation == KEYCTL_READ ||
        operation == KEYCTL_GET_SECURITY || operation == KEYCTL_CAPABILITIES;
}

static __always_inline u16 keyctl_output_arg_index(u64 operation)
{
    return operation == KEYCTL_CAPABILITIES ? 1 : 2;
}

static __always_inline u64 keyctl_output_user_ptr(struct pending_syscall *p)
{
    return p->args[0] == KEYCTL_CAPABILITIES ? p->args[1] : p->args[2];
}

static __always_inline u64 keyctl_output_user_len(
    struct pending_syscall *p,
    s64 ret_value)
{
    u64 requested_len = p->args[0] == KEYCTL_CAPABILITIES ?
        p->args[2] : p->args[3];
    u64 returned_len = (u64)ret_value;
    return requested_len < returned_len ? requested_len : returned_len;
}

static __always_inline int is_key_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ADD_KEY || sys_id == SYS_REQUEST_KEY ||
        is_keyctl_direct_syscall(sys_id);
}

#include "syscall_key_capture_direct_event_v2.h"
#include "syscall_key_emit_direct_event_v2.h"

#endif
