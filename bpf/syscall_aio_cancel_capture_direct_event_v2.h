#ifndef STRACE_GO_SYSCALL_AIO_CANCEL_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_CANCEL_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_aio_cancel_iocb_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = AIO_CANCEL_DIRECT_IOCB_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, AIO_CANCEL_DIRECT_IOCB_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, AIO_CANCEL_DIRECT_IOCB_SIZE, (void *)user_ptr);
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
            0,
            AIO_CANCEL_DIRECT_IOCB_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
