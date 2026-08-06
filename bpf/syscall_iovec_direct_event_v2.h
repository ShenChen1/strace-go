#ifndef STRACE_GO_SYSCALL_IOVEC_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_IOVEC_DIRECT_EVENT_V2_H

#define IOVEC_DIRECT_ELEM_SIZE 16
#define IOVEC_DIRECT_BYTES_MAX 256
#define IOVEC_DIRECT_SLOT_MAX 16
#define IOVEC_BASE_PAYLOAD_SLOT_MAX 7
#define IOVEC_BASE_PAYLOAD_BYTES_MAX 7
#define IOVEC_BASE_PAYLOAD_ARG1_BASE 120
#define IOVEC_BASE_PAYLOAD_ARG3_BASE 140
#define IOVEC_BASE_PAYLOAD_ARG151_BASE 160
#define IOVEC_BASE_PAYLOAD_CAPACITY \
    (IOVEC_BASE_PAYLOAD_SLOT_MAX * (PAYLOAD_TLV_HEADER_SIZE + IOVEC_BASE_PAYLOAD_BYTES_MAX))

static __always_inline int is_process_vm_iovec_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_PROCESS_VM_READV || sys_id == SYS_PROCESS_VM_WRITEV;
}

static __always_inline int is_iovec_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_READV || sys_id == SYS_WRITEV ||
        sys_id == SYS_PREADV || sys_id == SYS_PWRITEV ||
        sys_id == SYS_PREADV2 || sys_id == SYS_PWRITEV2 ||
        sys_id == SYS_VMSPLICE || is_process_vm_iovec_direct_syscall(sys_id) ||
        sys_id == SYS_PROCESS_MADVISE;
}

static __always_inline int is_iovec_base_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_WRITEV || sys_id == SYS_PWRITEV ||
        sys_id == SYS_PWRITEV2 || sys_id == SYS_VMSPLICE ||
        sys_id == SYS_PROCESS_VM_WRITEV;
}

static __always_inline int is_iovec_base_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_READV || sys_id == SYS_PREADV ||
        sys_id == SYS_PREADV2 || sys_id == SYS_PROCESS_VM_READV;
}

static __always_inline u32 iovec_direct_user_len(u64 count)
{
    if (count > 0xfffffffULL) {
        return 0xffffffffU;
    }
    return (u32)count * IOVEC_DIRECT_ELEM_SIZE;
}

static __always_inline u32 iovec_direct_copy_len(u64 count)
{
    if (count > IOVEC_DIRECT_SLOT_MAX) {
        return IOVEC_DIRECT_BYTES_MAX;
    }
    return (u32)count * IOVEC_DIRECT_ELEM_SIZE;
}

static __always_inline u32 iovec_base_payload_copy_len(u64 len)
{
    if (len > IOVEC_BASE_PAYLOAD_BYTES_MAX) {
        return IOVEC_BASE_PAYLOAD_BYTES_MAX;
    }
    return (u32)len;
}

static __always_inline u16 iovec_base_payload_arg_index(u16 iovec_arg_index, u16 slot)
{
    if (iovec_arg_index == 3) {
        return IOVEC_BASE_PAYLOAD_ARG3_BASE + slot;
    }
    if (iovec_arg_index == 151) {
        return IOVEC_BASE_PAYLOAD_ARG151_BASE + slot;
    }
    return IOVEC_BASE_PAYLOAD_ARG1_BASE + slot;
}

static __always_inline long probe_read_iovec_base_payload(u8 *payload_data, u32 copied_len, u64 user_ptr)
{
    if (copied_len == 1) return bpf_probe_read_user(payload_data, 1, (void *)user_ptr);
    if (copied_len == 2) return bpf_probe_read_user(payload_data, 2, (void *)user_ptr);
    if (copied_len == 3) return bpf_probe_read_user(payload_data, 3, (void *)user_ptr);
    if (copied_len == 4) return bpf_probe_read_user(payload_data, 4, (void *)user_ptr);
    if (copied_len == 5) return bpf_probe_read_user(payload_data, 5, (void *)user_ptr);
    if (copied_len == 6) return bpf_probe_read_user(payload_data, 6, (void *)user_ptr);
    if (copied_len == 7) return bpf_probe_read_user(payload_data, 7, (void *)user_ptr);
    return bpf_probe_read_user(payload_data, IOVEC_BASE_PAYLOAD_BYTES_MAX, (void *)user_ptr);
}

static __always_inline long dynptr_write_iovec_base_payload(
    struct bpf_dynptr *ptr,
    u32 offset,
    u8 *payload_data,
    u32 copied_len)
{
    if (copied_len == 1) return bpf_dynptr_write(ptr, offset, payload_data, 1, 0);
    if (copied_len == 2) return bpf_dynptr_write(ptr, offset, payload_data, 2, 0);
    if (copied_len == 3) return bpf_dynptr_write(ptr, offset, payload_data, 3, 0);
    if (copied_len == 4) return bpf_dynptr_write(ptr, offset, payload_data, 4, 0);
    if (copied_len == 5) return bpf_dynptr_write(ptr, offset, payload_data, 5, 0);
    if (copied_len == 6) return bpf_dynptr_write(ptr, offset, payload_data, 6, 0);
    if (copied_len == 7) return bpf_dynptr_write(ptr, offset, payload_data, 7, 0);
    return bpf_dynptr_write(ptr, offset, payload_data, IOVEC_BASE_PAYLOAD_BYTES_MAX, 0);
}

static __always_inline u32 capture_iovec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u64 count,
    u16 *event_flags)
{
    u32 user_len = iovec_direct_user_len(count);
    u32 target_len = iovec_direct_copy_len(count);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < IOVEC_DIRECT_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * IOVEC_DIRECT_ELEM_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 iov_data[IOVEC_DIRECT_ELEM_SIZE] = {};
        long err = bpf_probe_read_user(&iov_data, IOVEC_DIRECT_ELEM_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &iov_data, IOVEC_DIRECT_ELEM_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += IOVEC_DIRECT_ELEM_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_IOVEC,
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

static __always_inline u32 capture_iovec_base_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 payload_arg_index,
    u16 tlv_flags,
    u64 user_ptr,
    u64 user_len,
    u16 *event_flags)
{
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u8 payload_data[IOVEC_BASE_PAYLOAD_BYTES_MAX] = {};
    u32 copied_len = iovec_base_payload_copy_len(user_len);
    s32 probe_ret = 0;
    long err = probe_read_iovec_base_payload(payload_data, copied_len, user_ptr);
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
    } else {
        err = dynptr_write_iovec_base_payload(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            payload_data,
            copied_len);
        if (err < 0) {
            record_ringbuf_copy_fail();
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
            payload_arg_index,
            tlv_flags,
            (u32)user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_iovec_base_payloads_tlv_direct_for_arg(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 iovec_arg_index,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    if (!iovec_ptr || count == 0) {
        return 0;
    }

    u32 payload_size = 0;
    for (u16 i = 0; i < IOVEC_BASE_PAYLOAD_SLOT_MAX; i++) {
        if (i >= count) {
            break;
        }
        u64 slot = iovec_ptr + (u64)i * IOVEC_DIRECT_ELEM_SIZE;
        u64 base = 0;
        u64 len = 0;
        if (bpf_probe_read_user(&base, sizeof(base), (void *)slot) < 0) {
            break;
        }
        if (bpf_probe_read_user(&len, sizeof(len), (void *)(slot + 8)) < 0) {
            break;
        }
        payload_size += capture_iovec_base_tlv_direct(
            ptr,
            payload_offset + payload_size,
            iovec_base_payload_arg_index(iovec_arg_index, i),
            0,
            base,
            len,
            event_flags);
    }
    return payload_size;
}

static __noinline u32 capture_iovec_base_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    return capture_iovec_base_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        1,
        iovec_ptr,
        count,
        event_flags);
}

static __noinline u32 capture_iovec_base_payloads_arg151_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 iovec_ptr,
    u64 count,
    u16 *event_flags)
{
    return capture_iovec_base_payloads_tlv_direct_for_arg(
        ptr,
        payload_offset,
        151,
        iovec_ptr,
        count,
        event_flags);
}

static __always_inline u32 capture_iovec_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u32 payload_size = capture_iovec_tlv_direct(
        ptr,
        payload_offset,
        1,
        ctx->args[1],
        ctx->args[2],
        event_flags);
    if (is_process_vm_iovec_direct_syscall(sys_id)) {
        payload_size += capture_iovec_tlv_direct(
            ptr,
            payload_offset + payload_size,
            3,
            ctx->args[3],
            ctx->args[4],
            event_flags);
    }
    return payload_size;
}

static __noinline void emit_iovec_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + IOVEC_DIRECT_BYTES_MAX;
    if (is_process_vm_iovec_direct_syscall(sys_id)) {
        payload_capacity *= 2;
    }
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
    u32 payload_size = capture_iovec_payloads_tlv_direct(&ptr, payload_offset, sys_id, ctx, &flags);
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

static __noinline void emit_iovec_base_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u32 payload_capacity = IOVEC_BASE_PAYLOAD_CAPACITY;
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
    u32 payload_size = capture_iovec_base_payloads_tlv_direct(
        &ptr,
        payload_offset,
        ctx->args[1],
        ctx->args[2],
        &flags);
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

#endif
