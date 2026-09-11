#ifndef STRACE_GO_SYSCALL_BPF_MULTI_ARRAY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MULTI_ARRAY_DIRECT_EVENT_V2_H

struct bpf_multi_u64_array_capture_request {
    u64 user_ptr;
    u32 count;
    u16 arg_index;
    u16 *event_flags;
};

struct bpf_multi_u32_array_capture_request {
    u64 user_ptr;
    u32 count;
    u16 arg_index;
    u16 *event_flags;
};

static __always_inline u32 bpf_direct_multi_user_len(u32 count, u32 elem_size)
{
    if (elem_size != 0 && count > 0xffffffffU / elem_size) {
        return 0xffffffffU;
    }
    return count * elem_size;
}

static __always_inline u32 bpf_direct_multi_copy_entries(u32 count)
{
    if (count > BPF_DIRECT_MULTI_MAX_ENTRIES) {
        return BPF_DIRECT_MULTI_MAX_ENTRIES;
    }
    return count;
}

static __noinline u32 capture_bpf_multi_u32_array_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_multi_u32_array_capture_request *request)
{
    u64 user_ptr = request->user_ptr;
    u32 count = request->count;
    u16 arg_index = request->arg_index;
    u16 *event_flags = request->event_flags;
    if (!user_ptr || count == 0 || count > BPF_DIRECT_MULTI_COUNT_LIMIT) {
        return 0;
    }

    u32 copied_entries = bpf_direct_multi_copy_entries(count);
    u32 copied_len = copied_entries * sizeof(u32);
    u32 user_len = bpf_direct_multi_user_len(count, sizeof(u32));
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_MULTI_U32_ARRAY_MAX);
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

static __always_inline u32 capture_bpf_multi_u64_array_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_multi_u64_array_capture_request *request)
{
    u64 user_ptr = request->user_ptr;
    u32 count = request->count;
    u16 arg_index = request->arg_index;
    u16 *event_flags = request->event_flags;
    if (!user_ptr || count == 0 || count > BPF_DIRECT_MULTI_COUNT_LIMIT) {
        return 0;
    }

    u32 copied_entries = bpf_direct_multi_copy_entries(count);
    u32 copied_len = copied_entries * sizeof(u64);
    u32 user_len = bpf_direct_multi_user_len(count, sizeof(u64));
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_MULTI_U64_ARRAY_MAX);
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

#endif
