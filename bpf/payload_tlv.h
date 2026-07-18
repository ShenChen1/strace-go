#ifndef STRACE_GO_PAYLOAD_TLV_H
#define STRACE_GO_PAYLOAD_TLV_H

#define EVENT_FLAG_PAYLOAD_TLV 2
#define EVENT_FLAG_TRUNCATED 4
#define PAYLOAD_TLV_HEADER_SIZE 32
#define PAYLOAD_TLV_OPENAT_MAX 512
#define PAYLOAD_TLV_READ_MAX 512
#define PAYLOAD_TLV_WRITE_MAX 512
#define PAYLOAD_TLV_KIND_STRING 1
#define PAYLOAD_TLV_KIND_BYTES 2
#define PAYLOAD_TLV_KIND_EXEC_ARGS 6
#define PAYLOAD_TLV_FLAG_DIRECTION_OUT 1

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
