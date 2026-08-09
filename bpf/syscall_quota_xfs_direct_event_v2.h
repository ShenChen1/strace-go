#ifndef STRACE_GO_SYSCALL_QUOTA_XFS_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_QUOTA_XFS_DIRECT_EVENT_V2_H

#define QUOTA_XFS_ON 0x5801
#define QUOTA_XFS_OFF 0x5802
#define QUOTA_XFS_GET_QUOTA 0x5803
#define QUOTA_XFS_SET_QLIM 0x5804
#define QUOTA_XFS_GET_QSTAT 0x5805
#define QUOTA_XFS_QUOTA_RM 0x5806
#define QUOTA_XFS_QUOTA_SYNC 0x5807
#define QUOTA_XFS_GET_QSTATV 0x5808
#define QUOTA_XFS_GET_NEXT 0x5809

#define QUOTA_XFS_FLAGS_SIZE 4
#define QUOTA_XFS_DISK_SIZE 112
#define QUOTA_XFS_STAT_SIZE 80
#define QUOTA_XFS_STATV_SIZE 160

static __always_inline u32 quota_xfs_enter_struct_size(u32 command)
{
    if (command == QUOTA_XFS_ON || command == QUOTA_XFS_OFF ||
        command == QUOTA_XFS_QUOTA_RM) {
        return QUOTA_XFS_FLAGS_SIZE;
    }
    if (command == QUOTA_XFS_SET_QLIM) {
        return QUOTA_XFS_DISK_SIZE;
    }
    return 0;
}

static __always_inline u32 quota_xfs_exit_struct_size(u32 command)
{
    if (command == QUOTA_XFS_GET_QUOTA || command == QUOTA_XFS_GET_NEXT) {
        return QUOTA_XFS_DISK_SIZE;
    }
    if (command == QUOTA_XFS_GET_QSTAT) {
        return QUOTA_XFS_STAT_SIZE;
    }
    if (command == QUOTA_XFS_GET_QSTATV) {
        return QUOTA_XFS_STATV_SIZE;
    }
    return 0;
}

static __always_inline void *quota_xfs_dynptr_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 struct_size)
{
    if (struct_size == QUOTA_XFS_FLAGS_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_XFS_FLAGS_SIZE);
    }
    if (struct_size == QUOTA_XFS_DISK_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_XFS_DISK_SIZE);
    }
    if (struct_size == QUOTA_XFS_STAT_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_XFS_STAT_SIZE);
    }
    if (struct_size == QUOTA_XFS_STATV_SIZE) {
        return bpf_dynptr_data(ptr, data_offset, QUOTA_XFS_STATV_SIZE);
    }
    return 0;
}

static __always_inline u32 capture_quota_xfs_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 struct_size,
    u16 tlv_flags)
{
    if (!user_ptr || !struct_size) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = quota_xfs_dynptr_data(ptr, data_offset, struct_size);
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

#endif
