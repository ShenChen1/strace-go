#ifndef STRACE_GO_SYSCALL_FILE_ATTR_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FILE_ATTR_DIRECT_EVENT_V2_H

#define FILE_ATTR_DIRECT_BASE_SIZE 24
#define FILE_ATTR_DIRECT_EXTENSION_MAX 256
#define FILE_ATTR_DIRECT_PAGE_SIZE 4096

static __always_inline u32 capture_file_attr_base_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_size,
    u16 tlv_flags)
{
    if (raw_size < FILE_ATTR_DIRECT_BASE_SIZE ||
        raw_size > FILE_ATTR_DIRECT_PAGE_SIZE) {
        return 0;
    }

    u32 copied_len = FILE_ATTR_DIRECT_BASE_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (!user_ptr) {
        copied_len = 0;
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, FILE_ATTR_DIRECT_BASE_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            copied_len = 0;
            probe_ret = -1;
        } else {
            long err = bpf_probe_read_user(
                payload_data,
                FILE_ATTR_DIRECT_BASE_SIZE,
                (void *)user_ptr);
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
            arg_index,
            tlv_flags,
            FILE_ATTR_DIRECT_BASE_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_file_attr_extension_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_size,
    u16 *event_flags,
    u16 tlv_flags)
{
    if (raw_size <= FILE_ATTR_DIRECT_BASE_SIZE ||
        raw_size > FILE_ATTR_DIRECT_PAGE_SIZE) {
        return 0;
    }

    u64 raw_extension_len = raw_size - FILE_ATTR_DIRECT_BASE_SIZE;
    u32 user_len = payload_tlv_clamp_u32(raw_extension_len);
    u32 copied_len = payload_tlv_copy_len(raw_extension_len, FILE_ATTR_DIRECT_EXTENSION_MAX);
    u64 extension_ptr = 0;
    if (user_ptr) {
        extension_ptr = user_ptr + FILE_ATTR_DIRECT_BASE_SIZE;
    }

    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (!user_ptr || extension_ptr < user_ptr) {
        copied_len = 0;
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(
            ptr,
            data_offset,
            FILE_ATTR_DIRECT_EXTENSION_MAX);
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

    if (probe_ret == 0 && copied_len < user_len && event_flags) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            arg_index,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            extension_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_file_attr_tlvs_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 raw_size,
    u16 *event_flags,
    u16 tlv_flags)
{
    if (raw_size < FILE_ATTR_DIRECT_BASE_SIZE ||
        raw_size > FILE_ATTR_DIRECT_PAGE_SIZE) {
        return 0;
    }

    u32 payload_size = capture_file_attr_base_tlv_direct(
        ptr,
        payload_offset,
        arg_index,
        user_ptr,
        raw_size,
        tlv_flags);
    if (payload_size == 0) {
        return 0;
    }
    payload_size += capture_file_attr_extension_tlv_direct(
        ptr,
        payload_offset + payload_size,
        arg_index,
        user_ptr,
        raw_size,
        event_flags,
        tlv_flags);
    return payload_size;
}

#endif
