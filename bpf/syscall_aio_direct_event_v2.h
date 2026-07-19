#ifndef STRACE_GO_SYSCALL_AIO_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_AIO_DIRECT_EVENT_V2_H

#define AIO_SETUP_DIRECT_CTX_SIZE 8
#define AIO_SUBMIT_DIRECT_POINTER_SIZE 8
#define AIO_SUBMIT_DIRECT_POINTERS_MAX 512
#define AIO_SUBMIT_DIRECT_POINTER_SLOT_MAX 64
#define AIO_SUBMIT_DIRECT_IOCB_MAX 2
#define AIO_SUBMIT_DIRECT_IOCB_ARG_BASE 20
#define AIO_SUBMIT_DIRECT_IOCB_SIZE 64
#define AIO_SUBMIT_DIRECT_MAX_PAYLOAD \
    (PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_POINTERS_MAX + \
     AIO_SUBMIT_DIRECT_IOCB_MAX * (PAYLOAD_TLV_HEADER_SIZE + AIO_SUBMIT_DIRECT_IOCB_SIZE))
#define AIO_CANCEL_DIRECT_IOCB_SIZE 64

static __always_inline int is_aio_setup_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_SETUP;
}

static __always_inline int is_aio_submit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_SUBMIT;
}

static __always_inline int is_aio_cancel_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_IO_CANCEL;
}

static __always_inline int is_aio_direct_syscall(u32 sys_id)
{
    return is_aio_setup_direct_syscall(sys_id) ||
        is_aio_submit_direct_syscall(sys_id) ||
        is_aio_cancel_direct_syscall(sys_id);
}

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
    u64 iocb_ptr)
{
    if (!iocb_ptr || index >= AIO_SUBMIT_DIRECT_IOCB_MAX) {
        return 0;
    }

    u32 copied_len = AIO_SUBMIT_DIRECT_IOCB_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, AIO_SUBMIT_DIRECT_IOCB_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, AIO_SUBMIT_DIRECT_IOCB_SIZE, (void *)iocb_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            AIO_SUBMIT_DIRECT_IOCB_ARG_BASE + index,
            0,
            AIO_SUBMIT_DIRECT_IOCB_SIZE,
            copied_len,
            probe_ret,
            iocb_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
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
    for (u16 i = 0; i < AIO_SUBMIT_DIRECT_IOCB_MAX; i++) {
        if (count <= i) {
            break;
        }
        u64 iocb_ptr = 0;
        u64 slot = ctx->args[2] + (u64)i * AIO_SUBMIT_DIRECT_POINTER_SIZE;
        if (bpf_probe_read_user(&iocb_ptr, AIO_SUBMIT_DIRECT_POINTER_SIZE, (void *)slot) < 0) {
            continue;
        }
        payload_size += capture_aio_submit_iocb_tlv_direct(
            ptr,
            payload_offset + payload_size,
            i,
            iocb_ptr);
    }
    return payload_size;
}

static __always_inline void emit_aio_submit_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + AIO_SUBMIT_DIRECT_MAX_PAYLOAD;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_aio_submit_pointers_tlv_direct(&ptr, payload_offset, ctx);
    payload_size += capture_aio_submit_iocbs_tlv_direct(&ptr, payload_offset + payload_size, ctx);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

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

static __always_inline void emit_aio_cancel_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + AIO_CANCEL_DIRECT_IOCB_SIZE;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_aio_cancel_iocb_tlv_direct(&ptr, payload_offset, ctx->args[1]);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_aio_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    if (is_aio_submit_direct_syscall(sys_id)) {
        emit_aio_submit_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    if (is_aio_cancel_direct_syscall(sys_id)) {
        emit_aio_cancel_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, ts_ns);
}

static __always_inline void emit_aio_setup_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + AIO_SETUP_DIRECT_CTX_SIZE;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = 0;
    if (ret_value >= 0) {
        payload_size = capture_aio_setup_ctx_tlv_direct(&ptr, payload_offset, p->args[1]);
    }
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
