#ifndef STRACE_GO_SYSCALL_AIO_GETEVENTS_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_GETEVENTS_DIRECT_EVENT_V2_H

#define AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE 16
#define AIO_GETEVENTS_DIRECT_EVENT_SIZE 32
#define AIO_GETEVENTS_DIRECT_EVENTS_MAX 512
#define AIO_GETEVENTS_DIRECT_EVENT_SLOT_MAX 16
#define AIO_PGETEVENTS_DIRECT_SIGSET_SIZE 16
#define AIO_PGETEVENTS_DIRECT_SIGMASK_MAX 8
#define AIO_PGETEVENTS_DIRECT_MAX_PAYLOAD \
    (PAYLOAD_TLV_HEADER_SIZE + AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE + \
     PAYLOAD_TLV_HEADER_SIZE + AIO_PGETEVENTS_DIRECT_SIGSET_SIZE + \
     PAYLOAD_TLV_HEADER_SIZE + AIO_PGETEVENTS_DIRECT_SIGMASK_MAX)

static __always_inline int is_aio_getevents_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_GETEVENTS || sys_id == SYS_IO_PGETEVENTS;
}

static __always_inline int is_aio_pgetevents_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_PGETEVENTS;
}

static __always_inline u32 aio_getevents_user_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > 0x07ffffffLL) {
        return 0xffffffffU;
    }
    return (u32)count * AIO_GETEVENTS_DIRECT_EVENT_SIZE;
}

static __always_inline u32 aio_getevents_copy_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > AIO_GETEVENTS_DIRECT_EVENT_SLOT_MAX) {
        return AIO_GETEVENTS_DIRECT_EVENTS_MAX;
    }
    return (u32)count * AIO_GETEVENTS_DIRECT_EVENT_SIZE;
}

#include "syscall_aio_getevents_capture_direct_event_v2.h"
#include "syscall_aio_getevents_emit_direct_event_v2.h"

#endif
