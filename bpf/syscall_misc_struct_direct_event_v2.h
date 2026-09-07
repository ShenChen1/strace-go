#ifndef STRACE_GO_SYSCALL_MISC_STRUCT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MISC_STRUCT_DIRECT_EVENT_V2_H

#include "syscall_file_attr_direct_event_v2.h"

#define MISC_DIRECT_RLIMIT_SIZE 16
#define MISC_DIRECT_SYSINFO_SIZE 112
#define MISC_DIRECT_UTSNAME_SIZE 390
#define MISC_DIRECT_MAX_SIZE MISC_DIRECT_UTSNAME_SIZE

static __always_inline int is_misc_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_UNAME || sys_id == SYS_SYSINFO ||
        sys_id == SYS_GETRLIMIT || sys_id == SYS_SETRLIMIT || sys_id == SYS_PRLIMIT64 ||
        sys_id == SYS_FILE_GETATTR;
}

static __always_inline int is_misc_struct_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETRLIMIT || sys_id == SYS_PRLIMIT64;
}

static __always_inline int is_misc_struct_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_UNAME || sys_id == SYS_SYSINFO ||
        sys_id == SYS_GETRLIMIT || sys_id == SYS_PRLIMIT64 || sys_id == SYS_FILE_GETATTR;
}

static __always_inline u32 misc_struct_direct_size(u32 sys_id)
{
    if (sys_id == SYS_FILE_GETATTR) {
        return FILE_ATTR_DIRECT_BASE_SIZE;
    }
    if (sys_id == SYS_UNAME) {
        return MISC_DIRECT_UTSNAME_SIZE;
    }
    if (sys_id == SYS_SYSINFO) {
        return MISC_DIRECT_SYSINFO_SIZE;
    }
    return MISC_DIRECT_RLIMIT_SIZE;
}

static __always_inline u16 misc_struct_exit_arg_index(u32 sys_id)
{
    if (sys_id == SYS_FILE_GETATTR) {
        return 2;
    }
    if (sys_id == SYS_GETRLIMIT) {
        return 1;
    }
    if (sys_id == SYS_PRLIMIT64) {
        return 3;
    }
    return 0;
}

static __always_inline u64 misc_struct_exit_user_ptr(struct pending_syscall *p)
{
    if (p->sys_id == SYS_FILE_GETATTR) {
        return p->args[2];
    }
    if (p->sys_id == SYS_GETRLIMIT) {
        return p->args[1];
    }
    if (p->sys_id == SYS_PRLIMIT64) {
        return p->args[3];
    }
    return p->args[0];
}

static __always_inline u32 capture_misc_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    u16 arg_index,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 struct_size = misc_struct_direct_size(sys_id);
    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, MISC_DIRECT_MAX_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else if (sys_id == SYS_UNAME) {
        long err = bpf_probe_read_user(payload_data, MISC_DIRECT_UTSNAME_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    } else if (sys_id == SYS_SYSINFO) {
        long err = bpf_probe_read_user(payload_data, MISC_DIRECT_SYSINFO_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    } else {
        long err = bpf_probe_read_user(payload_data, MISC_DIRECT_RLIMIT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_misc_struct_enter_event_v2_direct_with_arg(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns,
    u16 arg_index,
    u64 user_ptr)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + MISC_DIRECT_MAX_SIZE;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_misc_struct_tlv_direct(&ptr, payload_offset, sys_id, arg_index, user_ptr, 0);
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

static __always_inline void emit_misc_struct_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    if (sys_id == SYS_PRLIMIT64) {
        emit_misc_struct_enter_event_v2_direct_with_arg(pid, tid, sys_id, ctx, ts_ns, 2, ctx->args[2]);
        return;
    }
    emit_misc_struct_enter_event_v2_direct_with_arg(pid, tid, sys_id, ctx, ts_ns, 1, ctx->args[1]);
}

static __always_inline void emit_misc_struct_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + MISC_DIRECT_MAX_SIZE;
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
    u16 arg_index = misc_struct_exit_arg_index(p->sys_id);
    u64 user_ptr = misc_struct_exit_user_ptr(p);
    u32 payload_size;
    if (p->sys_id == SYS_FILE_GETATTR) {
        payload_size = capture_file_attr_tlvs_direct(
            &ptr,
            payload_offset,
            arg_index,
            user_ptr,
            p->args[3],
            &flags,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    } else {
        payload_size = capture_misc_struct_tlv_direct(
            &ptr,
            payload_offset,
            p->sys_id,
            arg_index,
            user_ptr,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT);
    }
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
