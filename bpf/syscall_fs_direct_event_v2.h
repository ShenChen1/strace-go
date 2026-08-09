#ifndef STRACE_GO_SYSCALL_FS_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FS_DIRECT_EVENT_V2_H

#include "syscall_mount_setattr_direct_event_v2.h"
#include "syscall_mount_query_direct_event_v2.h"

#define FS_DIRECT_MOUNT_STRING_MAX 512
#define FS_DIRECT_MOUNT_TYPE_MAX 128
#define FS_DIRECT_FSCONFIG_KEY_MAX 257
#define FS_DIRECT_FSCONFIG_VALUE_MAX 4096
#define FS_DIRECT_FSCONFIG_SET_BINARY 2
#define FS_DIRECT_FSCONFIG_VALUE_LEN_MASK 8191
#define FS_DIRECT_GETDENTS64_BYTES_MAX 512
#define FS_DIRECT_PAYLOAD_CAPACITY MOUNT_SETATTR_DIRECT_PAYLOAD_CAPACITY

static __always_inline int is_fs_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_MOUNT || sys_id == SYS_UMOUNT2 ||
        sys_id == SYS_FSCONFIG || sys_id == SYS_MOUNT_SETATTR ||
        is_mount_query_direct_syscall(sys_id);
}

static __always_inline int is_getdents64_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETDENTS64;
}

static __always_inline int is_fs_direct_syscall(u32 sys_id)
{
    return is_fs_enter_direct_syscall(sys_id) ||
        is_getdents64_direct_syscall(sys_id);
}

static __always_inline u32 capture_fs_string_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u32 max_len)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (max_len == FS_DIRECT_FSCONFIG_VALUE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_VALUE_MAX);
    } else if (max_len == FS_DIRECT_FSCONFIG_KEY_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_KEY_MAX);
    } else if (max_len == FS_DIRECT_MOUNT_TYPE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_MOUNT_TYPE_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_MOUNT_STRING_MAX);
    }

    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, max_len, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > max_len) {
            copied_len = max_len;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            arg_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_fs_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_user_len,
    u16 *event_flags)
{
    u64 masked_len = raw_user_len & FS_DIRECT_FSCONFIG_VALUE_LEN_MASK;
    u32 user_len = payload_tlv_clamp_u32(masked_len);
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(masked_len, FS_DIRECT_FSCONFIG_VALUE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_FSCONFIG_VALUE_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
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
            PAYLOAD_TLV_KIND_BYTES,
            arg_index,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mount_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    u32 payload_size = capture_fs_string_tlv_direct(
        ptr,
        payload_offset,
        0,
        ctx->args[0],
        FS_DIRECT_MOUNT_STRING_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        ctx->args[1],
        FS_DIRECT_MOUNT_STRING_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        2,
        ctx->args[2],
        FS_DIRECT_MOUNT_TYPE_MAX);
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        4,
        ctx->args[4],
        FS_DIRECT_MOUNT_STRING_MAX);
    return payload_size;
}

static __always_inline u32 capture_fsconfig_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u32 payload_size = capture_fs_string_tlv_direct(
        ptr,
        payload_offset,
        2,
        ctx->args[2],
        FS_DIRECT_FSCONFIG_KEY_MAX);
    if (((u32)ctx->args[1]) == FS_DIRECT_FSCONFIG_SET_BINARY) {
        payload_size += capture_fs_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            3,
            ctx->args[3],
            ctx->args[4],
            event_flags);
        return payload_size;
    }
    payload_size += capture_fs_string_tlv_direct(
        ptr,
        payload_offset + payload_size,
        3,
        ctx->args[3],
        FS_DIRECT_FSCONFIG_VALUE_MAX);
    return payload_size;
}

static __always_inline u32 capture_fs_enter_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    if (sys_id == SYS_MOUNT) {
        return capture_mount_payload_tlv_direct(ptr, payload_offset, ctx);
    }
    if (sys_id == SYS_UMOUNT2) {
        return capture_fs_string_tlv_direct(
            ptr,
            payload_offset,
            0,
            ctx->args[0],
            FS_DIRECT_MOUNT_STRING_MAX);
    }
    if (sys_id == SYS_FSCONFIG) {
        return capture_fsconfig_payload_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    if (sys_id == SYS_MOUNT_SETATTR) {
        return capture_mount_setattr_enter_payload_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    if (is_mount_query_direct_syscall(sys_id)) {
        return capture_mnt_id_req_enter_tlv_direct(ptr, payload_offset, ctx, event_flags);
    }
    return 0;
}

static __always_inline void emit_fs_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = FS_DIRECT_PAYLOAD_CAPACITY;
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
    u32 payload_size = capture_fs_enter_payload_tlv_direct(&ptr, payload_offset, sys_id, ctx, &flags);
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

static __always_inline u32 capture_getdents64_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    if (ret_value <= 0) {
        return 0;
    }

    u64 user_ptr = p->args[1];
    u32 user_len = payload_tlv_clamp_u32((u64)ret_value);
    u32 copied_len = payload_tlv_copy_len((u64)ret_value, FS_DIRECT_GETDENTS64_BYTES_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
        copied_len = 0;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, FS_DIRECT_GETDENTS64_BYTES_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_getdents64_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + FS_DIRECT_GETDENTS64_BYTES_MAX;
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
    u32 payload_size = capture_getdents64_bytes_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
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
