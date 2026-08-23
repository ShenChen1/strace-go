#ifndef STRACE_GO_SYSCALL_MOUNT_SETATTR_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MOUNT_SETATTR_DIRECT_EVENT_V2_H

#include "syscall_path_direct_event_v2.h"
#include "syscall_fd_path_direct_event_v2.h"

#define MOUNT_SETATTR_BASE_SIZE 32
#define MOUNT_SETATTR_EXTENSION_MAX 256
#define MOUNT_SETATTR_DIRECT_PAYLOAD_CAPACITY \
    (FD_PATH_DIRECT_SECTION_MAX + 3 * PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX + \
     MOUNT_SETATTR_BASE_SIZE + MOUNT_SETATTR_EXTENSION_MAX)

static __always_inline u32 capture_mount_setattr_base_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    u64 user_ptr = ctx->args[3];
    u64 raw_size = ctx->args[4];
    if (raw_size < MOUNT_SETATTR_BASE_SIZE) {
        return 0;
    }

    u32 copied_len = MOUNT_SETATTR_BASE_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (!user_ptr) {
        copied_len = 0;
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, MOUNT_SETATTR_BASE_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            copied_len = 0;
            probe_ret = -1;
        } else {
            long err = bpf_probe_read_user(payload_data, MOUNT_SETATTR_BASE_SIZE, (void *)user_ptr);
            if (err < 0) {
                copied_len = 0;
                probe_ret = err;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            0,
            MOUNT_SETATTR_BASE_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mount_setattr_extension_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 user_ptr = ctx->args[3];
    u64 raw_size = ctx->args[4];
    if (raw_size <= MOUNT_SETATTR_BASE_SIZE) {
        return 0;
    }

    u64 raw_extension_len = raw_size - MOUNT_SETATTR_BASE_SIZE;
    u32 user_len = payload_tlv_clamp_u32(raw_extension_len);
    u32 copied_len = payload_tlv_copy_len(raw_extension_len, MOUNT_SETATTR_EXTENSION_MAX);
    u64 extension_ptr = 0;
    if (user_ptr) {
        extension_ptr = user_ptr + MOUNT_SETATTR_BASE_SIZE;
    }
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (!user_ptr || extension_ptr < user_ptr) {
        copied_len = 0;
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, MOUNT_SETATTR_EXTENSION_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            copied_len = 0;
            probe_ret = -1;
        } else {
            long err = bpf_probe_read_user(payload_data, copied_len, (void *)extension_ptr);
            if (err < 0) {
                copied_len = 0;
                probe_ret = err;
            }
        }
    }

    if (probe_ret == 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            3,
            0,
            user_len,
            copied_len,
            probe_ret,
            extension_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mount_setattr_enter_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (cfg && (*cfg & CONFIG_FD_STATE)) {
        payload_size += capture_fd_path_tlv_direct(
            ptr,
            payload_offset + payload_size,
            0,
            (s32)ctx->args[0]);
    }
    payload_size += capture_path_only_tlv_direct(
        ptr,
        payload_offset + payload_size,
        1,
        ctx->args[1]);
    payload_size += capture_mount_setattr_base_tlv_direct(
        ptr,
        payload_offset + payload_size,
        ctx);
    payload_size += capture_mount_setattr_extension_tlv_direct(
        ptr,
        payload_offset + payload_size,
        ctx,
        event_flags);
    return payload_size;
}

#endif
