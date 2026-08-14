#ifndef STRACE_GO_SYSCALL_QUOTA_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_QUOTA_CAPTURE_DIRECT_EVENT_V2_H

#include "syscall_path_capture_direct_event_v2.h"
#include "syscall_quota_xfs_direct_event_v2.h"

static __always_inline void *quota_direct_dynptr_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 struct_size)
{
    if (struct_size == QUOTA_DIRECT_FORMAT_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_FORMAT_SIZE);
    }
    if (struct_size == QUOTA_DIRECT_DQINFO_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_DQINFO_SIZE);
    }
    return bpf_dynptr_data(ptr, data_offset, QUOTA_DIRECT_DQBLK_SIZE);
}

static __always_inline u32 capture_quota_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 struct_size,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = quota_direct_dynptr_data(ptr, data_offset, struct_size);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, struct_size, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 quota_direct_enter_capacity(u32 sys_id, u32 command)
{
    u32 capacity = 0;
    if (sys_id == SYS_QUOTACTL) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    }
    if (command == QUOTA_DIRECT_ON) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + PATH_ONLY_DIRECT_PATH_MAX;
    } else if (command == QUOTA_DIRECT_SETINFO || command == QUOTA_DIRECT_SETQUOTA) {
        capacity += PAYLOAD_TLV_HEADER_SIZE + quota_direct_struct_size(command);
    } else {
        u32 xfs_size = quota_xfs_enter_struct_size(command);
        if (xfs_size > 0) {
            capacity += PAYLOAD_TLV_HEADER_SIZE + xfs_size;
        }
    }
    return capacity;
}

static __always_inline u32 capture_quota_enter_tlvs(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx)
{
    u32 payload_size = 0;
    u32 command = quota_direct_enter_command(ctx, sys_id);
    if (sys_id == SYS_QUOTACTL) {
        payload_size = capture_path_only_tlv_direct(ptr, payload_offset, 1, ctx->args[1]);
    }
    if (command == QUOTA_DIRECT_ON) {
        payload_size += capture_path_only_tlv_direct(
            ptr, payload_offset + payload_size, 3, ctx->args[3]);
    } else if (command == QUOTA_DIRECT_SETINFO || command == QUOTA_DIRECT_SETQUOTA) {
        payload_size += capture_quota_struct_tlv_direct(
            ptr,
            payload_offset + payload_size,
            ctx->args[3],
            quota_direct_struct_size(command),
            0);
    } else {
        u32 xfs_size = quota_xfs_enter_struct_size(command);
        if (xfs_size > 0) {
            payload_size += capture_quota_xfs_struct_tlv_direct(
                ptr, payload_offset + payload_size, ctx->args[3], xfs_size, 0);
        }
    }
    return payload_size;
}

#endif
