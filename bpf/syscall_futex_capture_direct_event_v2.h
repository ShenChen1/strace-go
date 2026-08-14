#ifndef STRACE_GO_SYSCALL_FUTEX_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FUTEX_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_futex_requeue_waiters_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = FUTEX_DIRECT_REQUEUE_WAITERS_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FUTEX_DIRECT_REQUEUE_WAITERS_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, FUTEX_DIRECT_REQUEUE_WAITERS_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            0,
            0,
            FUTEX_DIRECT_REQUEUE_WAITERS_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 futex_waitv_user_len_direct(u32 count)
{
    if (count > 0xffffffffU / FUTEX_DIRECT_WAITV_ELEM_SIZE) {
        return 0xffffffffU;
    }
    return (u32)(count * FUTEX_DIRECT_WAITV_ELEM_SIZE);
}

static __always_inline u32 futex_waitv_copy_len_direct(u32 count)
{
    if (count > FUTEX_DIRECT_WAITV_MAX) {
        count = FUTEX_DIRECT_WAITV_MAX;
    }
    return (u32)count * FUTEX_DIRECT_WAITV_ELEM_SIZE;
}

static __always_inline u32 capture_futex_waitv_waiters_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 count,
    u16 *event_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 user_len = futex_waitv_user_len_direct(count);
    u32 requested_len = futex_waitv_copy_len_direct(count);
    if (requested_len == 0) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = FUTEX_DIRECT_WAITV_ELEM_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, FUTEX_DIRECT_WAITV_ELEM_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, FUTEX_DIRECT_WAITV_ELEM_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        } else if (requested_len > FUTEX_DIRECT_WAITV_ELEM_SIZE) {
            u32 rest_len = requested_len - FUTEX_DIRECT_WAITV_ELEM_SIZE;
            void *payload_rest = bpf_dynptr_data(
                ptr,
                data_offset + FUTEX_DIRECT_WAITV_ELEM_SIZE,
                FUTEX_DIRECT_WAITV_MAX_BYTES - FUTEX_DIRECT_WAITV_ELEM_SIZE);
            if (!payload_rest) {
                record_ringbuf_copy_fail();
            } else {
                long rest_err = bpf_probe_read_user(
                    payload_rest,
                    rest_len,
                    (void *)(user_ptr + FUTEX_DIRECT_WAITV_ELEM_SIZE));
                if (rest_err == 0) {
                    copied_len = requested_len;
                }
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && requested_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            0,
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
