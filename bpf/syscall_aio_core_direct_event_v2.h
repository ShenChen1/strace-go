#ifndef STRACE_GO_SYSCALL_AIO_CORE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_CORE_DIRECT_EVENT_V2_H

#define AIO_SETUP_DIRECT_CTX_SIZE 8
#define AIO_SUBMIT_DIRECT_POINTER_SIZE 8
#define AIO_SUBMIT_DIRECT_POINTERS_MAX 64
#define AIO_SUBMIT_DIRECT_POINTER_SLOT_MAX 8
#define AIO_SUBMIT_DIRECT_IOCB_MAX 5
#define AIO_SUBMIT_DIRECT_IOCB_ARG_BASE 20
#define AIO_SUBMIT_DIRECT_IOCB_SIZE 64
#define AIO_SUBMIT_DIRECT_IOVEC_MAX 2
#define AIO_SUBMIT_DIRECT_IOVEC_SIZE 16
#define AIO_SUBMIT_DIRECT_IOVEC_ARG_BASE 40
#define AIO_SUBMIT_DIRECT_BUF_ARG_BASE 60
#define AIO_SUBMIT_DIRECT_BUF_MAX 32
#define AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX 4
#define AIO_SUBMIT_DIRECT_MAX_PAYLOAD \
    (PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_POINTERS_MAX + \
     AIO_SUBMIT_DIRECT_IOCB_MAX * (PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_IOCB_SIZE + \
      PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_IOVEC_MAX * AIO_SUBMIT_DIRECT_IOVEC_SIZE))
#define AIO_CANCEL_DIRECT_IOCB_SIZE 64

static __always_inline int is_aio_setup_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_SETUP;
}

static __always_inline int is_aio_submit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_SUBMIT;
}

static __always_inline int is_aio_cancel_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_CANCEL;
}

static __always_inline int is_aio_direct_syscall(u32 sys_id)
{
    return is_aio_setup_direct_syscall(sys_id) ||
        is_aio_getevents_direct_syscall(sys_id) ||
        is_aio_submit_direct_syscall(sys_id) ||
        is_aio_cancel_direct_syscall(sys_id);
}

#endif
