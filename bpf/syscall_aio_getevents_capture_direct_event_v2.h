#ifndef STRACE_GO_SYSCALL_AIO_GETEVENTS_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_GETEVENTS_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_aio_getevents_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            4,
            0,
            AIO_GETEVENTS_DIRECT_TIMEOUT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_aio_getevents_events_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u64 user_ptr = p->args[3];
    u32 user_len = aio_getevents_user_len(ret_value);
    u32 target_len = aio_getevents_copy_len(ret_value);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < AIO_GETEVENTS_DIRECT_EVENT_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * AIO_GETEVENTS_DIRECT_EVENT_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 event_data[AIO_GETEVENTS_DIRECT_EVENT_SIZE] = {};
        long err = bpf_probe_read_user(&event_data, AIO_GETEVENTS_DIRECT_EVENT_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &event_data, AIO_GETEVENTS_DIRECT_EVENT_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += AIO_GETEVENTS_DIRECT_EVENT_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_aio_pgetevents_sigset_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 *sigmask_ptr,
    u64 *sigset_size)
{
    if (!user_ptr) {
        return 0;
    }

    u64 sigset_data[2] = {};
    u32 copied_len = AIO_PGETEVENTS_DIRECT_SIGSET_SIZE;
    s32 probe_ret = 0;
    long err = bpf_probe_read_user(&sigset_data, AIO_PGETEVENTS_DIRECT_SIGSET_SIZE, (void *)user_ptr);
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
    } else {
        err = bpf_dynptr_write(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            &sigset_data,
            AIO_PGETEVENTS_DIRECT_SIGSET_SIZE,
            0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            probe_ret = err;
            copied_len = 0;
        } else {
            *sigmask_ptr = sigset_data[0];
            *sigset_size = sigset_data[1];
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            5,
            0,
            AIO_PGETEVENTS_DIRECT_SIGSET_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_aio_pgetevents_sigmask_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 user_len)
{
    if (!user_ptr || user_len == 0 || user_len > AIO_PGETEVENTS_DIRECT_SIGMASK_MAX) {
        return 0;
    }

    u8 sigmask_data[AIO_PGETEVENTS_DIRECT_SIGMASK_MAX] = {};
    u32 copied_len = (u32)user_len;
    asm volatile ("" : "+r"(copied_len));
    if (copied_len > AIO_PGETEVENTS_DIRECT_SIGMASK_MAX) {
        copied_len = AIO_PGETEVENTS_DIRECT_SIGMASK_MAX;
    }
    s32 probe_ret = 0;
    long err = bpf_probe_read_user(&sigmask_data, copied_len, (void *)user_ptr);
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
    } else {
        err = bpf_dynptr_write(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            &sigmask_data,
            copied_len,
            0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            5,
            0,
            (u32)user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
