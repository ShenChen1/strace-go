#ifndef STRACE_GO_SYSCALL_POLL_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_POLL_CAPTURE_DIRECT_EVENT_V2_H

struct poll_fd_capture_request {
    u64 user_ptr;
    u64 count;
    u16 tlv_flags;
};

static __always_inline u32 capture_poll_fds_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    const struct poll_fd_capture_request *request,
    u16 *event_flags)
{
    u32 user_len = poll_fds_user_len(request->count);
    u32 target_len = poll_fds_copy_len(request->count);
    if (user_len == 0 || !request->user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < POLL_DIRECT_FD_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * POLL_DIRECT_FD_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 fd_data[POLL_DIRECT_FD_SIZE] = {};
        long err = bpf_probe_read_user(&fd_data, POLL_DIRECT_FD_SIZE, (void *)(request->user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &fd_data, POLL_DIRECT_FD_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += POLL_DIRECT_FD_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            0,
            request->tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_poll_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = POLL_DIRECT_TIMEOUT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, POLL_DIRECT_TIMEOUT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, POLL_DIRECT_TIMEOUT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            2,
            tlv_flags,
            POLL_DIRECT_TIMEOUT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_poll_sigmask_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 sigset_size)
{
    if (!user_ptr || sigset_size == 0) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = POLL_DIRECT_SIGMASK_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, POLL_DIRECT_SIGMASK_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, POLL_DIRECT_SIGMASK_SIZE, (void *)user_ptr);
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
            0,
            payload_tlv_clamp_u32(sigset_size),
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
