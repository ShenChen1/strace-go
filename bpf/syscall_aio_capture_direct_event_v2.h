#ifndef STRACE_GO_SYSCALL_AIO_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_aio_setup_ctx_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = AIO_SETUP_DIRECT_CTX_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, AIO_SETUP_DIRECT_CTX_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, AIO_SETUP_DIRECT_CTX_SIZE, (void *)user_ptr);
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
            AIO_SETUP_DIRECT_CTX_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 aio_submit_pointer_user_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > 0x1fffffffLL) {
        return 0xffffffffU;
    }
    return (u32)count * AIO_SUBMIT_DIRECT_POINTER_SIZE;
}

static __always_inline u32 aio_submit_pointer_copy_len(s64 count)
{
    if (count <= 0) {
        return 0;
    }
    if (count > AIO_SUBMIT_DIRECT_POINTERS_MAX / AIO_SUBMIT_DIRECT_POINTER_SIZE) {
        return AIO_SUBMIT_DIRECT_POINTERS_MAX;
    }
    return (u32)count * AIO_SUBMIT_DIRECT_POINTER_SIZE;
}

static __always_inline u32 capture_aio_submit_pointers_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    s64 count = (s64)ctx->args[1];
    u32 user_len = aio_submit_pointer_user_len(count);
    u32 copied_len = aio_submit_pointer_copy_len(count);
    u64 user_ptr = ctx->args[2];
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    u32 target_len = copied_len;
    copied_len = 0;
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_POINTER_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * AIO_SUBMIT_DIRECT_POINTER_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u64 iocb_ptr = 0;
        long err = bpf_probe_read_user(&iocb_ptr, AIO_SUBMIT_DIRECT_POINTER_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &iocb_ptr, AIO_SUBMIT_DIRECT_POINTER_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += AIO_SUBMIT_DIRECT_POINTER_SIZE;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            2,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_aio_submit_iocb_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 index,
    u64 iocb_ptr,
    u64 *iocb_out)
{
    if (!iocb_ptr || index >= AIO_SUBMIT_DIRECT_IOCB_MAX) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    long err = bpf_probe_read_user(iocb_out, AIO_SUBMIT_DIRECT_IOCB_SIZE, (void *)iocb_ptr);
    if (err < 0) {
        probe_ret = err;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            AIO_SUBMIT_DIRECT_IOCB_ARG_BASE + index,
            0,
            AIO_SUBMIT_DIRECT_IOCB_SIZE,
            err < 0 ? 0 : AIO_SUBMIT_DIRECT_IOCB_SIZE,
            probe_ret,
            iocb_ptr)) {
        return 0;
    }
    if (err >= 0) {
        err = bpf_dynptr_write(ptr, data_offset, iocb_out, AIO_SUBMIT_DIRECT_IOCB_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
        }
    }
    return PAYLOAD_TLV_HEADER_SIZE + (err < 0 ? 0 : AIO_SUBMIT_DIRECT_IOCB_SIZE);
}

// IMPACT: PREADV/PWRITEV iocbs point at an iovec array; copy a bounded prefix
// so the Go formatter can render iov_base/iov_len pairs instead of a pointer.
static __always_inline u32 capture_aio_submit_iocb_iovec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 index,
    const u64 *iocb_data)
{
    u16 opcode = (u16)(iocb_data[2] & 0xffff);
    if (opcode != 7 && opcode != 8) {
        return 0;
    }
    u64 iov_ptr = iocb_data[3];
    u64 iov_count = iocb_data[4];
    if (!iov_ptr || iov_count == 0 || index >= AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX) {
        return 0;
    }
    if (iov_count > AIO_SUBMIT_DIRECT_IOVEC_MAX) {
        iov_count = AIO_SUBMIT_DIRECT_IOVEC_MAX;
    }

    u32 user_len = (u32)iov_count * AIO_SUBMIT_DIRECT_IOVEC_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    s32 probe_ret = 0;
    u32 copied_len = 0;
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_IOVEC_MAX; i++) {
        if (i >= iov_count) {
            break;
        }
        u64 slot[2] = {};
        long err = bpf_probe_read_user(
            slot,
            AIO_SUBMIT_DIRECT_IOVEC_SIZE,
            (void *)(iov_ptr + (u64)i * AIO_SUBMIT_DIRECT_IOVEC_SIZE));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        err = bpf_dynptr_write(
            ptr,
            data_offset + copied_len,
            slot,
            AIO_SUBMIT_DIRECT_IOVEC_SIZE,
            0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += AIO_SUBMIT_DIRECT_IOVEC_SIZE;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_IOVEC,
            AIO_SUBMIT_DIRECT_IOVEC_ARG_BASE + index,
            0,
            user_len,
            copied_len,
            probe_ret,
            iov_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

// IMPACT: PWRITE iocbs point at a bounded data buffer; capture a prefix so the
// Go formatter can render it as an escaped string instead of a raw pointer.
static __always_inline u32 capture_aio_submit_iocb_buf_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 index,
    const u64 *iocb_data)
{
    u16 opcode = (u16)(iocb_data[2] & 0xffff);
    if (opcode != 1) {
        return 0;
    }
    u64 buf_ptr = iocb_data[3];
    u64 buf_len = iocb_data[4];
    if (!buf_ptr || buf_len == 0 || index >= AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX) {
        return 0;
    }
    if (buf_len > AIO_SUBMIT_DIRECT_BUF_MAX) {
        buf_len = AIO_SUBMIT_DIRECT_BUF_MAX;
    }

    u8 buf_data[AIO_SUBMIT_DIRECT_BUF_MAX] = {};
    s32 probe_ret = 0;
    long err = bpf_probe_read_user(buf_data, AIO_SUBMIT_DIRECT_BUF_MAX, (void *)buf_ptr);
    if (err < 0) {
        probe_ret = err;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            AIO_SUBMIT_DIRECT_BUF_ARG_BASE + index,
            0,
            (u32)buf_len,
            err < 0 ? 0 : (u32)buf_len,
            probe_ret,
            buf_ptr)) {
        return 0;
    }
    if (err >= 0) {
        err = bpf_dynptr_write(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            buf_data,
            (u32)buf_len,
            0);
        if (err < 0) {
            record_ringbuf_copy_fail();
        }
    }
    return PAYLOAD_TLV_HEADER_SIZE + (err < 0 ? 0 : (u32)buf_len);
}

static __always_inline u32 capture_aio_submit_iocbs_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    s64 count = (s64)ctx->args[1];
    if (count <= 0 || !ctx->args[2]) {
        return 0;
    }

    u32 payload_size = 0;
    u64 iocb_buf[AIO_SUBMIT_DIRECT_IOCB_SIZE / 8] = {};
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_IOCB_MAX; i++) {
        if (count <= i) {
            break;
        }
        u64 iocb_ptr = 0;
        u64 slot = ctx->args[2] + (u64)i * AIO_SUBMIT_DIRECT_POINTER_SIZE;
        if (bpf_probe_read_user(&iocb_ptr, AIO_SUBMIT_DIRECT_POINTER_SIZE, (void *)slot) < 0) {
            continue;
        }
        u32 iocb_size = capture_aio_submit_iocb_tlv_direct(
            ptr,
            payload_offset + payload_size,
            i,
            iocb_ptr,
            iocb_buf);
        payload_size += iocb_size;
    }
    return payload_size;
}

// IMPACT: PREADV/PWRITEV nested iovec arrays are captured by a dedicated
// program so the iocb array capture stays within verifier limits.
static __always_inline u32 capture_aio_submit_iocbs_iovec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    s64 count = (s64)ctx->args[1];
    if (count <= 0 || !ctx->args[2]) {
        return 0;
    }

    u32 payload_size = 0;
    u64 iocb_buf[AIO_SUBMIT_DIRECT_IOCB_SIZE / 8] = {};
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX; i++) {
        if (count <= i) {
            break;
        }
        u64 iocb_ptr = 0;
        if (bpf_probe_read_user(
                &iocb_ptr,
                AIO_SUBMIT_DIRECT_POINTER_SIZE,
                (void *)(ctx->args[2] + (u64)i * AIO_SUBMIT_DIRECT_POINTER_SIZE)) < 0) {
            continue;
        }
        if (!iocb_ptr ||
            bpf_probe_read_user(iocb_buf, AIO_SUBMIT_DIRECT_IOCB_SIZE, (void *)iocb_ptr) < 0) {
            continue;
        }
        payload_size += capture_aio_submit_iocb_iovec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            i,
            iocb_buf);
    }
    return payload_size;
}

// IMPACT: PWRITE data buffer prefixes are captured by their own dedicated
// program so neither nested capture loop exceeds verifier limits.
static __always_inline u32 capture_aio_submit_iocbs_buf_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx)
{
    s64 count = (s64)ctx->args[1];
    if (count <= 0 || !ctx->args[2]) {
        return 0;
    }

    u32 payload_size = 0;
    u64 iocb_buf[AIO_SUBMIT_DIRECT_IOCB_SIZE / 8] = {};
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_NESTED_IOCB_MAX; i++) {
        if (count <= i) {
            break;
        }
        u64 iocb_ptr = 0;
        if (bpf_probe_read_user(
                &iocb_ptr,
                AIO_SUBMIT_DIRECT_POINTER_SIZE,
                (void *)(ctx->args[2] + (u64)i * AIO_SUBMIT_DIRECT_POINTER_SIZE)) < 0) {
            continue;
        }
        if (!iocb_ptr ||
            bpf_probe_read_user(iocb_buf, AIO_SUBMIT_DIRECT_IOCB_SIZE, (void *)iocb_ptr) < 0) {
            continue;
        }
        payload_size += capture_aio_submit_iocb_buf_tlv_direct(
            ptr,
            payload_offset + payload_size,
            i,
            iocb_buf);
    }
    return payload_size;
}

#endif
