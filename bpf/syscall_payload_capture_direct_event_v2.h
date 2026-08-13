#ifndef STRACE_GO_SYSCALL_PAYLOAD_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PAYLOAD_CAPTURE_DIRECT_EVENT_V2_H

#include "syscall_exec_capture_direct_event_v2.h"

static __always_inline u32 capture_openat_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_OPENAT_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, PAYLOAD_TLV_OPENAT_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > PAYLOAD_TLV_OPENAT_MAX) {
                copied_len = PAYLOAD_TLV_OPENAT_MAX;
            } else {
                copied_len = (u32)n;
            }
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

static __always_inline u32 capture_write_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6],
    u16 *event_flags)
{
    u64 user_ptr = args[1];
    u32 user_len = payload_tlv_clamp_u32(args[2]);
    u32 copied_len = payload_tlv_copy_len(args[2], PAYLOAD_TLV_WRITE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (copied_len > 0) {
        if (!user_ptr) {
            probe_ret = -1;
            copied_len = 0;
        } else {
            void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_WRITE_MAX);
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
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    u64 args[6],
    u16 *event_flags)
{
    if (sys_id == SYS_OPEN || sys_id == SYS_CREAT) {
        return capture_openat_path_tlv_direct(ptr, payload_offset, 0, args[0]);
    }
    if (sys_id == SYS_OPENAT) {
        return capture_openat_path_tlv_direct(ptr, payload_offset, 1, args[1]);
    }
    if (sys_id == SYS_EXECVE) {
        struct exec_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.path_index = 0;
        request.argv_index = 1;
        request.path_ptr = args[0];
        request.argv_ptr = args[1];
        request.env_ptr = args[2];
        return capture_exec_tlv_direct(&request);
    }
    if (sys_id == SYS_EXECVEAT) {
        struct exec_capture_request request = {};
        request.ptr = ptr;
        request.payload_offset = payload_offset;
        request.path_index = 1;
        request.argv_index = 2;
        request.path_ptr = args[1];
        request.argv_ptr = args[2];
        request.env_ptr = args[3];
        return capture_exec_tlv_direct(&request);
    }
    if (is_write_payload_direct_syscall(sys_id)) {
        return capture_write_bytes_tlv_direct(ptr, payload_offset, args, event_flags);
    }
    return 0;
}

static __always_inline u32 capture_read_bytes_tlv_direct(
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
    u32 copied_len = payload_tlv_copy_len((u64)ret_value, PAYLOAD_TLV_READ_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
        copied_len = 0;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_READ_MAX);
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

#endif
