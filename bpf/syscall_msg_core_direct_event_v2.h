#ifndef STRACE_GO_SYSCALL_MSG_CORE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MSG_CORE_DIRECT_EVENT_V2_H

#define MSGHDR_USER_SIZE 56
#define MMSGHDR_USER_SIZE 64
#define MMSGHDR_DIRECT_SLOT_MAX 4
#define MMSGHDR_DIRECT_BYTES_MAX (MMSGHDR_DIRECT_SLOT_MAX * MMSGHDR_USER_SIZE)
#define MMSGHDR_SECOND_IOV_ARG 151
#define MMSGHDR_THIRD_IOV_ARG 181
#define MMSGHDR_FOURTH_IOV_ARG 211
#define MSGHDR_NAME_OFFSET 0
#define MSGHDR_NAMELEN_OFFSET 8
#define MSGHDR_IOV_OFFSET 16
#define MSGHDR_IOVLEN_OFFSET 24
#define MSG_DIRECT_SOCKADDR_MAX 128
#define MSG_DIRECT_TIMESPEC_SIZE 16
#include "syscall_msg_control_direct_event_v2.h"

#define MSG_DIRECT_TIMESPEC_MAX (PAYLOAD_TLV_HEADER_SIZE + MSG_DIRECT_TIMESPEC_SIZE)
#define MSG_DIRECT_MSGHDR_MAX (PAYLOAD_TLV_HEADER_SIZE + MSGHDR_USER_SIZE)
#define MSG_DIRECT_MMSGHDR_MAX (PAYLOAD_TLV_HEADER_SIZE + MMSGHDR_DIRECT_BYTES_MAX)
#define MSG_DIRECT_MMSG_ENTER_MAX \
    (MSG_DIRECT_MMSGHDR_MAX + MSG_DIRECT_TIMESPEC_MAX)
#define MSG_DIRECT_SINGLE_ENTER_MAX \
    (MSG_DIRECT_MSGHDR_MAX + \
     (PAYLOAD_TLV_HEADER_SIZE + IOVEC_DIRECT_BYTES_MAX) + \
     MSG_DIRECT_CMSG_TLV_MAX)
#define MSG_DIRECT_ENTER_MAX MSG_DIRECT_MMSG_ENTER_MAX
#define MSG_DIRECT_SENDMSG_BASE_ENTER_MAX IOVEC_BASE_PAYLOAD_CAPACITY
#define MSG_DIRECT_MMSG_BASE_ENTER_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + IOVEC_DIRECT_BYTES_MAX)
#define MSG_DIRECT_MMSG_BYTES_ENTER_MAX IOVEC_BASE_PAYLOAD_CAPACITY
#define MSG_DIRECT_RECVMSG_EXIT_MAX \
    (MSG_DIRECT_MSGHDR_MAX + \
     IOVEC_BASE_EXIT_PAYLOAD_CAPACITY)
#define MSG_DIRECT_MMSG_EXIT_MAX (MSG_DIRECT_MMSGHDR_MAX + MSG_DIRECT_TIMESPEC_MAX)
#define MSG_DIRECT_RECVMMSG_BASE_EXIT_MAX IOVEC_BASE_EXIT_PAYLOAD_CAPACITY
#define MSG_DIRECT_RECVMSG_NAME_EXIT_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + MSG_DIRECT_SOCKADDR_MAX)
#define MSG_DIRECT_RECVMSG_CONTROL_EXIT_MAX MSG_DIRECT_CMSG_TLV_MAX

struct msg_direct_iov {
    u64 ptr;
    u64 count;
};

struct msg_direct_name {
    u64 ptr;
    u32 len;
};

static __always_inline int is_msg_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDMSG || sys_id == SYS_RECVMSG ||
        sys_id == SYS_SENDMMSG || sys_id == SYS_RECVMMSG;
}

static __always_inline int is_single_msg_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDMSG || sys_id == SYS_RECVMSG;
}

static __always_inline int is_mmsg_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SENDMMSG || sys_id == SYS_RECVMMSG;
}

static __always_inline u16 mmsg_iovec_arg_index_for_slot(u16 slot)
{
    switch (slot) {
    case 1:
        return MMSGHDR_SECOND_IOV_ARG;
    case 2:
        return MMSGHDR_THIRD_IOV_ARG;
    case 3:
        return MMSGHDR_FOURTH_IOV_ARG;
    default:
        return 1;
    }
}

static __always_inline int msg_direct_read_iov(u64 msg_ptr, struct msg_direct_iov *iov)
{
    iov->ptr = 0;
    iov->count = 0;
    if (!msg_ptr) {
        return -1;
    }
    if (bpf_probe_read_user(&iov->ptr, sizeof(iov->ptr), (void *)(msg_ptr + MSGHDR_IOV_OFFSET)) < 0) {
        return -1;
    }
    if (bpf_probe_read_user(&iov->count, sizeof(iov->count), (void *)(msg_ptr + MSGHDR_IOVLEN_OFFSET)) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline int msg_direct_read_name(u64 msg_ptr, struct msg_direct_name *name)
{
    name->ptr = 0;
    name->len = 0;
    if (!msg_ptr) {
        return -1;
    }
    if (bpf_probe_read_user(&name->ptr, sizeof(name->ptr), (void *)(msg_ptr + MSGHDR_NAME_OFFSET)) < 0) {
        return -1;
    }
    if (bpf_probe_read_user(&name->len, sizeof(name->len), (void *)(msg_ptr + MSGHDR_NAMELEN_OFFSET)) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline void save_pending_msg_syscall_args(
    u32 tid,
    u32 pid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 enter_time,
    s32 stack_id)
{
    struct pending_syscall p = {};

    p.enter_time = enter_time;
    p.args[0] = ctx->args[0];
    p.args[1] = ctx->args[1];
    p.args[2] = ctx->args[2];
    p.args[3] = ctx->args[3];
    p.args[4] = ctx->args[4];
    p.args[5] = ctx->args[5];
    p.pid = pid;
    p.sys_id = sys_id;
    p.tid = tid;
    p.stack_id = stack_id;

    if (sys_id == SYS_RECVMSG) {
        struct msg_direct_name name = {};
        if (msg_direct_read_name(ctx->args[1], &name) == 0) {
            p.aux0 = name.len;
        }
    }

    if (bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY) != 0) {
        record_pending_update_fail();
    }
}

#endif
