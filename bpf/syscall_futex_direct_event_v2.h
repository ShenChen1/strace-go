#ifndef STRACE_GO_SYSCALL_FUTEX_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FUTEX_DIRECT_EVENT_V2_H

#define FUTEX_DIRECT_CMD_MASK 0x7f
#define FUTEX_DIRECT_WAIT 0
#define FUTEX_DIRECT_LOCK_PI 6
#define FUTEX_DIRECT_WAIT_BITSET 9
#define FUTEX_DIRECT_WAIT_REQUEUE_PI 11
#define FUTEX_DIRECT_LOCK_PI2 13
#define FUTEX_DIRECT_WAITV_ELEM_SIZE 24
#define FUTEX_DIRECT_WAITV_MAX 128
#define FUTEX_DIRECT_WAITV_MAX_BYTES 3072
#define FUTEX_DIRECT_REQUEUE_WAITERS_SIZE 48

static __always_inline int futex_has_timeout_direct(u64 op)
{
    u64 base_op = op & FUTEX_DIRECT_CMD_MASK;
    return base_op == FUTEX_DIRECT_WAIT ||
        base_op == FUTEX_DIRECT_LOCK_PI ||
        base_op == FUTEX_DIRECT_WAIT_BITSET ||
        base_op == FUTEX_DIRECT_WAIT_REQUEUE_PI ||
        base_op == FUTEX_DIRECT_LOCK_PI2;
}

#include "syscall_futex_capture_direct_event_v2.h"
#include "syscall_futex_emit_direct_event_v2.h"

#endif
