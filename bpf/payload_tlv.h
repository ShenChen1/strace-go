#ifndef STRACE_GO_PAYLOAD_TLV_H
#define STRACE_GO_PAYLOAD_TLV_H

#define EVENT_FLAG_PAYLOAD_TLV 2
#define EVENT_FLAG_TRUNCATED 4
#define EVENT_FLAG_EXIT_FRAGMENT 8
#define PAYLOAD_TLV_HEADER_SIZE 32
#define PAYLOAD_TLV_OPENAT_MAX 512
#define PAYLOAD_TLV_READ_MAX 512
#define PAYLOAD_TLV_WRITE_MAX 512
#define PAYLOAD_TLV_KIND_STRING 1
#define PAYLOAD_TLV_KIND_BYTES 2
#define PAYLOAD_TLV_KIND_STRUCT 3
#define PAYLOAD_TLV_KIND_IOVEC 4
#define PAYLOAD_TLV_KIND_SOCKADDR 5
#define PAYLOAD_TLV_KIND_EXEC_ARGS 6
#define PAYLOAD_TLV_KIND_CMSG 7
#define PAYLOAD_TLV_KIND_FD_STATE 8
#define PAYLOAD_TLV_KIND_FD_PATH 9
#define PAYLOAD_TLV_FD_STATE_ARG_INDEX 0xffff
#define PAYLOAD_TLV_FD_PATH_CWD_ARG_INDEX 0xfffe
#define PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX 0xfffd
#define PAYLOAD_TLV_FLAG_DIRECTION_OUT 1
#define FD_STATE_SNAPSHOT_SIZE 48
#define FD_STATE_FLAG_IDENTITY 1
#define FD_STATE_FLAG_OFFSET 2

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

#endif
