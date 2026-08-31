#ifndef STRACE_GO_PAYLOAD_TLV_H
#define STRACE_GO_PAYLOAD_TLV_H

#include "event_abi_generated.h"

struct fd_state_snapshot {
    s32 fd;
    u32 flags;
    u32 mode;
    u32 reserved;
    u64 dev;
    u64 rdev;
    u64 inode;
    s64 offset;
};

struct eventfd_state_snapshot {
    u64 count;
    s32 id;
    u32 semaphore;
};

struct namespace_snapshot {
    u64 flags;
    u32 cgroup;
    u32 ipc;
    u32 mnt;
    u32 net;
    u32 pid;
    u32 time;
    u32 uts;
    u32 user;
};

_Static_assert(sizeof(struct namespace_snapshot) == NAMESPACE_SNAPSHOT_SIZE,
    "namespace snapshot size drift");

struct payload_tlv_header {
    u16 kind;
    u16 arg_index;
    u16 flags;
    u16 reserved;
    u32 user_len;
    u32 copied_len;
    s32 probe_ret;
    u32 reserved2;
    u64 user_ptr;
};

static __always_inline u32 payload_tlv_clamp_u32(u64 value)
{
    if (value > 0xffffffffULL) {
        return 0xffffffffU;
    }
    return (u32)value;
}

static __always_inline u32 payload_tlv_copy_len(u64 value, u32 max)
{
    if (value > max) {
        return max;
    }
    return (u32)value;
}

static __always_inline u32 payload_tlv_data_bucket(u32 copied_len)
{
    if (copied_len == 0) {
        return 0;
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_64) {
        return PAYLOAD_TLV_DATA_BUCKET_64;
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_128) {
        return PAYLOAD_TLV_DATA_BUCKET_128;
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_256) {
        return PAYLOAD_TLV_DATA_BUCKET_256;
    }
    return PAYLOAD_TLV_DATA_BUCKET_512;
}

static __always_inline void *payload_tlv_data_direct(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 copied_len)
{
    if (copied_len == 0) {
        return 0;
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_64) {
        return bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_DATA_BUCKET_64);
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_128) {
        return bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_DATA_BUCKET_128);
    }
    if (copied_len <= PAYLOAD_TLV_DATA_BUCKET_256) {
        return bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_DATA_BUCKET_256);
    }
    return bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_DATA_BUCKET_512);
}

#endif
