#ifndef STRACE_GO_SYSCALL_PATH_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PATH_CAPTURE_DIRECT_EVENT_V2_H

#define PATH_ONLY_DIRECT_PATH_MAX 4096
#define PATH_ONLY_DIRECT_FIRST_CHUNK 2048
#define PATH_ONLY_DIRECT_SECOND_CHUNK 2049
#define DUAL_PATH_DIRECT_PATH_MAX 512

static __always_inline u32 capture_path_only_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PATH_ONLY_DIRECT_PATH_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, PATH_ONLY_DIRECT_FIRST_CHUNK, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n >= PATH_ONLY_DIRECT_FIRST_CHUNK) {
                void *tail = bpf_dynptr_data(
                    ptr,
                    data_offset + PATH_ONLY_DIRECT_FIRST_CHUNK - 1,
                    PATH_ONLY_DIRECT_SECOND_CHUNK);
                if (!tail) {
                    record_ringbuf_copy_fail();
                    probe_ret = -1;
                } else {
                    long tail_len = bpf_probe_read_user_str(
                        tail,
                        PATH_ONLY_DIRECT_SECOND_CHUNK,
                        (void *)(user_ptr + PATH_ONLY_DIRECT_FIRST_CHUNK - 1));
                    if (tail_len < 0) {
                        probe_ret = tail_len;
                        copied_len = PATH_ONLY_DIRECT_FIRST_CHUNK - 1;
                    } else {
                        copied_len = PATH_ONLY_DIRECT_FIRST_CHUNK - 1 + (u32)tail_len;
                        if (copied_len >= PATH_ONLY_DIRECT_PATH_MAX) {
                            char last_byte = 0;
                            bpf_probe_read_user(
                                &last_byte,
                                1,
                                (void *)(user_ptr + PATH_ONLY_DIRECT_PATH_MAX - 1));
                            void *last = bpf_dynptr_data(
                                ptr,
                                data_offset + PATH_ONLY_DIRECT_PATH_MAX - 1,
                                1);
                            if (last) {
                                *(char *)last = last_byte;
                            }
                            copied_len = PATH_ONLY_DIRECT_PATH_MAX;
                            // IMPACT: a NUL right at the PATH_MAX boundary means
                            // the path is exactly PATH_MAX-1 chars and complete;
                            // only a non-NUL boundary byte proves truncation.
                            if (last_byte != 0) {
                                record_payload_truncated_event();
                            }
                        }
                    }
                }
            } else {
                copied_len = (u32)n;
            }
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

static __always_inline u32 capture_dual_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, DUAL_PATH_DIRECT_PATH_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, DUAL_PATH_DIRECT_PATH_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > DUAL_PATH_DIRECT_PATH_MAX) {
                copied_len = DUAL_PATH_DIRECT_PATH_MAX;
            } else {
                copied_len = (u32)n;
            }
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
