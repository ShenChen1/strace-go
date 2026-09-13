#ifndef STRACE_GO_SYSCALL_BPF_NESTED_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_NESTED_CAPTURE_DIRECT_EVENT_V2_H

struct bpf_nested_bytes_capture_request {
    u64 user_ptr;
    u32 user_len;
    u32 max_len;
    u32 storage_len;
    u16 arg_index;
    u16 *event_flags;
};

static __always_inline u32 capture_bpf_license_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_LICENSE_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, BPF_DIRECT_LICENSE_MAX, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > BPF_DIRECT_LICENSE_MAX) {
            copied_len = BPF_DIRECT_LICENSE_MAX;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            BPF_DIRECT_PROG_LOAD_LICENSE_ARG,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void *bpf_nested_bytes_storage_direct(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 storage_len)
{
    if (storage_len == BPF_DIRECT_BYTES_BUCKET_20) {
        return bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BYTES_BUCKET_20);
    }
    if (storage_len == BPF_DIRECT_BYTES_BUCKET_64) {
        return bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BYTES_BUCKET_64);
    }
    if (storage_len == BPF_DIRECT_BYTES_BUCKET_256) {
        return bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BYTES_BUCKET_256);
    }
    if (storage_len == BPF_DIRECT_BYTES_BUCKET_512) {
        return bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BYTES_BUCKET_512);
    }
    return 0;
}

static __always_inline u32 capture_bpf_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_nested_bytes_capture_request *request)
{
    u64 user_ptr = request->user_ptr;
    u32 user_len = request->user_len;
    u32 max_len = request->max_len;
    u32 storage_len = request->storage_len;
    if (!user_ptr || user_len == 0 || max_len == 0 || storage_len < max_len) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(user_len, max_len);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_nested_bytes_storage_direct(ptr, data_offset, storage_len);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        /* Preserve a verifier-visible bound after dynptr pointer selection. */
        asm volatile("" : "+r"(copied_len));
        if (copied_len > BPF_DIRECT_BYTES_BUCKET_512) {
            copied_len = BPF_DIRECT_BYTES_BUCKET_512;
        }
        if (copied_len > storage_len) {
            copied_len = storage_len;
        }
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *request->event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            request->arg_index,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_bpf_string_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 max_len,
    u16 arg_index)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (max_len == BPF_DIRECT_OBJ_PATH_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_OBJ_PATH_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX);
    }
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, max_len, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > max_len) {
            copied_len = max_len;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            arg_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
