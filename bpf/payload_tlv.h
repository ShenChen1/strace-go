#ifndef STRACE_GO_PAYLOAD_TLV_H
#define STRACE_GO_PAYLOAD_TLV_H

#define EVENT_FLAG_PAYLOAD_TLV 2
#define PAYLOAD_TLV_HEADER_SIZE 32
#define PAYLOAD_TLV_READ_MAX 512
#define PAYLOAD_TLV_WRITE_MAX 512
#define PAYLOAD_TLV_KIND_BYTES 2
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

static __always_inline void payload_tlv_write_header(
    struct bpf_event *e,
    u16 kind,
    u16 arg_index,
    u16 flags,
    u32 user_len,
    u32 copied_len,
    s32 probe_ret,
    u64 user_ptr)
{
    struct payload_tlv_header *header = (void *)e->str_arg;
    header->kind = kind;
    header->arg_index = arg_index;
    header->flags = flags;
    header->reserved = 0;
    header->user_len = user_len;
    header->copied_len = copied_len;
    header->probe_ret = probe_ret;
    header->reserved2 = 0;
    header->user_ptr = user_ptr;
}

static __always_inline void capture_write_tlv(struct bpf_event *e)
{
    if (e->sys_id != SYS_WRITE) {
        return;
    }

    u32 user_len = payload_tlv_clamp_u32(e->args[2]);
    u32 copied_len = payload_tlv_copy_len(e->args[2], PAYLOAD_TLV_WRITE_MAX);
    s32 probe_ret = 0;

    if (copied_len > 0) {
        if (!e->args[1]) {
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(
                e->str_arg + PAYLOAD_TLV_HEADER_SIZE,
                copied_len,
                (void *)e->args[1]);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    }

    payload_tlv_write_header(
        e,
        PAYLOAD_TLV_KIND_BYTES,
        1,
        0,
        user_len,
        copied_len,
        probe_ret,
        e->args[1]);
    e->data_len = PAYLOAD_TLV_HEADER_SIZE + copied_len;
    e->event_flags |= EVENT_FLAG_PAYLOAD_TLV;
}

static __always_inline void capture_read_tlv(struct bpf_event *e)
{
    if (e->sys_id != SYS_READ || e->ret <= 0) {
        return;
    }

    u32 user_len = payload_tlv_clamp_u32((u64)e->ret);
    u32 copied_len = payload_tlv_copy_len((u64)e->ret, PAYLOAD_TLV_READ_MAX);
    s32 probe_ret = 0;

    if (!e->args[1]) {
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(
            e->str_arg + PAYLOAD_TLV_HEADER_SIZE,
            copied_len,
            (void *)e->args[1]);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    payload_tlv_write_header(
        e,
        PAYLOAD_TLV_KIND_BYTES,
        1,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT,
        user_len,
        copied_len,
        probe_ret,
        e->args[1]);
    e->data_len = PAYLOAD_TLV_HEADER_SIZE + copied_len;
    e->event_flags |= EVENT_FLAG_PAYLOAD_TLV;
}

#endif
