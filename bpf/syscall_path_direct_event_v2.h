#ifndef STRACE_GO_SYSCALL_PATH_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PATH_DIRECT_EVENT_V2_H

#include "syscall_path_capture_direct_event_v2.h"

static __always_inline int is_path_only_arg0_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ACCESS || sys_id == SYS_CHDIR || sys_id == SYS_CHROOT ||
        sys_id == SYS_CHMOD || sys_id == SYS_CHOWN || sys_id == SYS_LCHOWN ||
        sys_id == SYS_MKDIR || sys_id == SYS_MKNOD || sys_id == SYS_RMDIR ||
        sys_id == SYS_UNLINK || sys_id == SYS_SWAPON || sys_id == SYS_SWAPOFF ||
        sys_id == SYS_ACCT || sys_id == SYS_TRUNCATE || sys_id == SYS_FSOPEN;
}

static __always_inline int is_path_only_arg1_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_MKDIRAT || sys_id == SYS_MKNODAT || sys_id == SYS_FCHOWNAT ||
        sys_id == SYS_UNLINKAT || sys_id == SYS_FCHMODAT || sys_id == SYS_FACCESSAT ||
        sys_id == SYS_FACCESSAT2 || sys_id == SYS_FSPICK || sys_id == SYS_OPEN_TREE;
}

static __always_inline int is_path_only_direct_syscall(u32 sys_id)
{
    return is_path_only_arg0_direct_syscall(sys_id) ||
        is_path_only_arg1_direct_syscall(sys_id);
}

static __always_inline int is_dual_path_0_1_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RENAME || sys_id == SYS_LINK || sys_id == SYS_SYMLINK;
}

static __always_inline int is_dual_path_0_2_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SYMLINKAT;
}

static __always_inline int is_dual_path_1_3_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_RENAMEAT || sys_id == SYS_RENAMEAT2 || sys_id == SYS_LINKAT;
}

static __always_inline int is_dual_path_direct_syscall(u32 sys_id)
{
    return is_dual_path_0_1_direct_syscall(sys_id) ||
        is_dual_path_0_2_direct_syscall(sys_id) ||
        is_dual_path_1_3_direct_syscall(sys_id);
}

static __always_inline void emit_path_only_enter_event_v2_direct_with_path(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 path_arg,
    u64 user_ptr)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_path_only_tlv_direct(&ptr, payload_offset, path_arg, user_ptr);
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

    body.capture_len = payload_size;
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_path_only_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    if (is_path_only_arg1_direct_syscall(sys_id)) {
        emit_path_only_enter_event_v2_direct_with_path(pid, tid, sys_id, ctx, ts_ns, 1, ctx->args[1]);
        return;
    }
    emit_path_only_enter_event_v2_direct_with_path(pid, tid, sys_id, ctx, ts_ns, 0, ctx->args[0]);
}

static __always_inline void emit_path_only_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u16 path_arg = 0;
    if (is_path_only_arg1_direct_syscall(p->sys_id)) {
        path_arg = 1;
    }

    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_path_only_tlv_direct(&ptr, payload_offset, path_arg, p->args[path_arg]);
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

static __always_inline void emit_dual_path_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u16 first_arg = 0;
    u16 second_arg = 1;
    u64 first_ptr = p->args[0];
    u64 second_ptr = p->args[1];
    if (is_dual_path_0_2_direct_syscall(p->sys_id)) {
        second_arg = 2;
        second_ptr = p->args[2];
    } else if (is_dual_path_1_3_direct_syscall(p->sys_id)) {
        first_arg = 1;
        first_ptr = p->args[1];
        second_arg = 3;
        second_ptr = p->args[3];
    }

    u32 payload_capacity = 2 * (PAYLOAD_TLV_HEADER_SIZE + DUAL_PATH_DIRECT_PATH_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_dual_path_tlv_direct(
        &ptr,
        payload_offset,
        first_arg,
        first_ptr);
    payload_size += capture_dual_path_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        second_arg,
        second_ptr);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
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

static __always_inline void emit_dual_path_enter_event_v2_direct_with_paths(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 first_arg,
    u64 first_ptr,
    u16 second_arg,
    u64 second_ptr)
{
    u32 payload_capacity = 2 * (PAYLOAD_TLV_HEADER_SIZE + DUAL_PATH_DIRECT_PATH_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_dual_path_tlv_direct(&ptr, payload_offset, first_arg, first_ptr);
    payload_size += capture_dual_path_tlv_direct(&ptr, payload_offset + payload_size, second_arg, second_ptr);
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

    body.capture_len = payload_size;
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_dual_path_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    if (is_dual_path_0_2_direct_syscall(sys_id)) {
        emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, sys_id, ctx, ts_ns, 0, ctx->args[0], 2, ctx->args[2]);
        return;
    }
    if (is_dual_path_1_3_direct_syscall(sys_id)) {
        emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, sys_id, ctx, ts_ns, 1, ctx->args[1], 3, ctx->args[3]);
        return;
    }
    emit_dual_path_enter_event_v2_direct_with_paths(pid, tid, sys_id, ctx, ts_ns, 0, ctx->args[0], 1, ctx->args[1]);
}

#endif
