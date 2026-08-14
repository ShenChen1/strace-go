#ifndef STRACE_GO_SYSCALL_PRCTL_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PRCTL_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_prctl_name_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 user_len = 0;
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, PRCTL_DIRECT_NAME_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, PRCTL_DIRECT_NAME_SIZE, (void *)user_ptr);
        if (n < 0) {
            if (tlv_flags & PAYLOAD_TLV_FLAG_DIRECTION_OUT) {
                probe_ret = n;
            } else {
                long raw_n = bpf_probe_read_user(
                    payload_data,
                    PRCTL_DIRECT_NAME_SIZE - 1,
                    (void *)user_ptr);
                if (raw_n < 0) {
                    probe_ret = n;
                } else {
                    user_len = PRCTL_DIRECT_NAME_SIZE;
                    copied_len = PRCTL_DIRECT_NAME_SIZE - 1;
                }
            }
        } else if (n >= PRCTL_DIRECT_NAME_SIZE && !(tlv_flags & PAYLOAD_TLV_FLAG_DIRECTION_OUT)) {
            user_len = PRCTL_DIRECT_NAME_SIZE;
            copied_len = PRCTL_DIRECT_NAME_SIZE - 1;
        } else {
            copied_len = (u32)n;
            user_len = copied_len;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            1,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_prctl_uint32_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = PRCTL_DIRECT_UINT32_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, PRCTL_DIRECT_UINT32_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, PRCTL_DIRECT_UINT32_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            PRCTL_DIRECT_UINT32_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
