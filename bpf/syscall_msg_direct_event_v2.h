#ifndef STRACE_GO_SYSCALL_MSG_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MSG_DIRECT_EVENT_V2_H

#define MSGHDR_USER_SIZE 56
#define MMSGHDR_USER_SIZE 64
#define MMSGHDR_DIRECT_SLOT_MAX 2
#define MMSGHDR_DIRECT_BYTES_MAX (MMSGHDR_DIRECT_SLOT_MAX * MMSGHDR_USER_SIZE)
#define MMSGHDR_SECOND_IOV_ARG 151
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
    (MSG_DIRECT_MMSGHDR_MAX + \
     2 * (PAYLOAD_TLV_HEADER_SIZE + IOVEC_DIRECT_BYTES_MAX) + \
     MSG_DIRECT_TIMESPEC_MAX)
#define MSG_DIRECT_SINGLE_ENTER_MAX \
    (MSG_DIRECT_MSGHDR_MAX + \
     (PAYLOAD_TLV_HEADER_SIZE + IOVEC_DIRECT_BYTES_MAX) + \
     MSG_DIRECT_CMSG_TLV_MAX)
#define MSG_DIRECT_ENTER_MAX MSG_DIRECT_MMSG_ENTER_MAX
#define MSG_DIRECT_SENDMSG_BASE_ENTER_MAX IOVEC_BASE_PAYLOAD_CAPACITY
#define MSG_DIRECT_SENDMMSG_BASE_ENTER_MAX \
    (2 * IOVEC_BASE_PAYLOAD_CAPACITY)
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

static __always_inline u32 capture_msghdr_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 msg_ptr,
    u16 *event_flags)
{
    if (!msg_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MSGHDR_USER_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSGHDR_USER_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, MSGHDR_USER_SIZE, (void *)msg_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            tlv_flags,
            MSGHDR_USER_SIZE,
            copied_len,
            probe_ret,
            msg_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mmsghdr_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 msg_ptr,
    u64 count,
    u16 *event_flags)
{
    if (!msg_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MMSGHDR_USER_SIZE;
    u32 user_len = MMSGHDR_USER_SIZE;
    if (count > 1) {
        copied_len = MMSGHDR_DIRECT_BYTES_MAX;
        user_len = MMSGHDR_DIRECT_BYTES_MAX;
    }
    if (count > MMSGHDR_DIRECT_SLOT_MAX) {
        user_len = (u32)(MMSGHDR_DIRECT_SLOT_MAX + 1) * MMSGHDR_USER_SIZE;
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MMSGHDR_DIRECT_BYTES_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else if (count > 1) {
        long err = bpf_probe_read_user(payload_data, MMSGHDR_DIRECT_BYTES_MAX, (void *)msg_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    } else {
        long err = bpf_probe_read_user(payload_data, MMSGHDR_USER_SIZE, (void *)msg_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            msg_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_msg_name_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 msg_ptr,
    u32 copy_limit,
    u16 *event_flags)
{
    struct msg_direct_name name = {};
    if (msg_direct_read_name(msg_ptr, &name) < 0 || !name.ptr || name.len == 0) {
        return 0;
    }

    u32 user_len = name.len;
    u32 copied_len = name.len;
    if (copy_limit > 0 && copy_limit < copied_len) {
        copied_len = copy_limit;
    }
    if (copied_len > MSG_DIRECT_SOCKADDR_MAX) {
        copied_len = MSG_DIRECT_SOCKADDR_MAX;
    }
    s32 probe_ret = 0;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSG_DIRECT_SOCKADDR_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)name.ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_SOCKADDR,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            name.ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mmsg_timespec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 timeout_ptr,
    u16 *event_flags)
{
    if (!timeout_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = MSG_DIRECT_TIMESPEC_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSG_DIRECT_TIMESPEC_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, MSG_DIRECT_TIMESPEC_SIZE, (void *)timeout_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            4,
            tlv_flags,
            MSG_DIRECT_TIMESPEC_SIZE,
            copied_len,
            probe_ret,
            timeout_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
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

    bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY);
}

static __always_inline u32 capture_mmsg_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (ctx->args[2] == 0) {
        return 0;
    }

    u64 msg_ptr = ctx->args[1];
    u32 payload_size = capture_mmsghdr_tlv_direct(
        ptr,
        payload_offset,
        0,
        msg_ptr,
        ctx->args[2],
        event_flags);

    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return payload_size;
    }

    payload_size += capture_iovec_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        iov.ptr,
        iov.count,
        event_flags);

    if (ctx->id == SYS_RECVMMSG) {
        payload_size += capture_mmsg_timespec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            0,
            ctx->args[4],
            event_flags);
    }

    if (ctx->args[2] <= 1) {
        return payload_size;
    }

    u64 msg1_ptr = msg_ptr + MMSGHDR_USER_SIZE;
    struct msg_direct_iov iov1 = {};
    if (msg_direct_read_iov(msg1_ptr, &iov1) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_tlv_direct(
        ptr,
        payload_offset + payload_size,
        MMSGHDR_SECOND_IOV_ARG,
        iov1.ptr,
        iov1.count,
        event_flags);

    return payload_size;
}

static __always_inline u32 capture_sendmmsg_base0_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (ctx->args[2] == 0) {
        return 0;
    }

    u64 msg_ptr = ctx->args[1];
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }

    return capture_iovec_base_payloads_tlv_direct(
        ptr,
        payload_offset,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_sendmmsg_base1_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (ctx->args[2] <= 1) {
        return 0;
    }

    u64 msg_ptr = ctx->args[1];
    u64 msg1_ptr = msg_ptr + MMSGHDR_USER_SIZE;
    struct msg_direct_iov iov1 = {};
    if (msg_direct_read_iov(msg1_ptr, &iov1) < 0) {
        return 0;
    }
    return capture_iovec_base_payloads_arg151_tlv_direct(
        ptr,
        payload_offset,
        iov1.ptr,
        iov1.count,
        event_flags);
}

static __always_inline u32 capture_single_msg_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    u32 payload_size = capture_msghdr_tlv_direct(
        ptr,
        payload_offset,
        0,
        msg_ptr,
        event_flags);
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return payload_size;
    }

    payload_size += capture_iovec_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        iov.ptr,
        iov.count,
        event_flags);
    payload_size += capture_msg_control_tlv_direct(
        ptr,
        payload_offset + payload_size,
        0,
        msg_ptr,
        event_flags);

    return payload_size;
}

static __always_inline u32 capture_sendmsg_base_enter_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 msg_ptr = ctx->args[1];
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return 0;
    }

    return capture_iovec_base_payloads_tlv_direct(
        ptr,
        payload_offset,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline void emit_msg_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_SINGLE_ENTER_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_single_msg_enter_payloads_tlv_direct(&ptr, payload_offset, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_sendmsg_base_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_SENDMSG_BASE_ENTER_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_sendmsg_base_enter_payloads_tlv_direct(&ptr, payload_offset, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_mmsg_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_ENTER_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_mmsg_enter_payloads_tlv_direct(&ptr, payload_offset, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_sendmmsg_base0_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_SENDMMSG_BASE_ENTER_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_sendmmsg_base0_enter_payloads_tlv_direct(&ptr, payload_offset, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_sendmmsg_base1_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_SENDMMSG_BASE_ENTER_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_sendmmsg_base1_enter_payloads_tlv_direct(&ptr, payload_offset, ctx, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline u32 capture_single_msg_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    u64 msg_ptr = p->args[1];
    u32 payload_size = capture_msghdr_tlv_direct(
        ptr,
        payload_offset,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        msg_ptr,
        event_flags);

    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg_ptr, &iov) < 0) {
        return payload_size;
    }
    payload_size += capture_iovec_base_exit_payloads_tlv_direct(
        ptr,
        payload_offset + payload_size,
        iov.ptr,
        iov.count,
        event_flags);
    return payload_size;
}

static __always_inline u32 capture_mmsg_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    if (p->args[2] == 0) {
        return 0;
    }

    u32 payload_size = capture_mmsghdr_tlv_direct(
        ptr,
        payload_offset,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        p->args[1],
        p->args[2],
        event_flags);
    if (p->sys_id == SYS_RECVMMSG && ret_value > 0) {
        payload_size += capture_mmsg_timespec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            p->args[4],
            event_flags);
    }
    return payload_size;
}

static __always_inline u32 capture_recvmmsg_base0_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    if (p->args[2] == 0) {
        return 0;
    }

    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(p->args[1], &iov) < 0) {
        return 0;
    }
    return capture_iovec_base_exit_payloads_tlv_direct(
        ptr,
        payload_offset,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline u32 capture_recvmmsg_base1_exit_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    if (p->args[2] <= 1) {
        return 0;
    }

    u64 msg1_ptr = p->args[1] + MMSGHDR_USER_SIZE;
    struct msg_direct_iov iov = {};
    if (msg_direct_read_iov(msg1_ptr, &iov) < 0) {
        return 0;
    }
    return capture_iovec_base_exit_payloads_arg151_tlv_direct(
        ptr,
        payload_offset,
        iov.ptr,
        iov.count,
        event_flags);
}

static __always_inline void emit_recvmsg_control_exit_fragment_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (p->sys_id != SYS_RECVMSG || ret_value < 0) {
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_RECVMSG_CONTROL_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_EXIT_FRAGMENT;
    u32 payload_size = capture_msg_control_tlv_direct(
        &ptr,
        payload_offset,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        p->args[1],
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_recvmsg_name_exit_fragment_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (p->sys_id != SYS_RECVMSG || ret_value <= 0) {
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_RECVMSG_NAME_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_EXIT_FRAGMENT;
    u32 payload_size = capture_msg_name_tlv_direct(&ptr, payload_offset, p->args[1], p->aux0, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_single_msg_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (p->sys_id != SYS_RECVMSG || ret_value <= 0) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_RECVMSG_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_single_msg_exit_payloads_tlv_direct(&ptr, payload_offset, p, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_mmsg_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (ret_value <= 0) {
        emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_MMSG_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_mmsg_exit_payloads_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_recvmmsg_base0_exit_fragment_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (ret_value <= 0) {
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_RECVMMSG_BASE_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_EXIT_FRAGMENT;
    u32 payload_size = capture_recvmmsg_base0_exit_payloads_tlv_direct(&ptr, payload_offset, p, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_recvmmsg_base1_exit_fragment_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (ret_value <= 0) {
        return;
    }

    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + MSG_DIRECT_RECVMMSG_BASE_EXIT_MAX;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_EXIT_FRAGMENT;
    u32 payload_size = capture_recvmmsg_base1_exit_payloads_tlv_direct(&ptr, payload_offset, p, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
