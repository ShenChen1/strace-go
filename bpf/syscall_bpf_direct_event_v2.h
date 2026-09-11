#ifndef STRACE_GO_SYSCALL_BPF_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_DIRECT_EVENT_V2_H

#define BPF_DIRECT_ATTR_MAX 512

static __always_inline int is_bpf_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_BPF;
}

static __always_inline u32 capture_bpf_attr_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u64 requested_len,
    u16 *event_flags)
{
    if (!user_ptr || requested_len == 0) {
        return 0;
    }

    u32 user_len = payload_tlv_clamp_u32(requested_len);
    u32 copied_len = payload_tlv_copy_len(requested_len, BPF_DIRECT_ATTR_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_ATTR_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
        if (err < 0) {
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
            1,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#include "syscall_bpf_nested_direct_event_v2.h"
#include "syscall_bpf_tracing_multi_direct_event_v2.h"
#include "syscall_bpf_exit_direct_event_v2.h"

static __noinline void emit_bpf_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 cmd = ctx->args[0];
    u64 attr_ptr = ctx->args[1];
    u64 attr_size = ctx->args[2];
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_ATTR_MAX + BPF_DIRECT_NESTED_CAPACITY;
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
    u32 payload_size = capture_bpf_attr_tlv_direct(&ptr, payload_offset, attr_ptr, attr_size, &flags);
    payload_size += capture_bpf_nested_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        cmd,
        attr_ptr,
        attr_size,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header *header = event_v2_header_from_dynptr_direct(&ptr);
    if (!header) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    init_syscall_event_v2_header_direct(header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);

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

static __noinline void emit_bpf_prog_load_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 attr_ptr = ctx->args[1];
    u64 attr_size = ctx->args[2];
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_ATTR_MAX + BPF_DIRECT_PROG_LOAD_BASE_CAPACITY;
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
    u32 payload_size = capture_bpf_attr_tlv_direct(&ptr, payload_offset, attr_ptr, attr_size, &flags);
    payload_size += capture_bpf_prog_load_nested_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header *header = event_v2_header_from_dynptr_direct(&ptr);
    if (!header) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    init_syscall_event_v2_header_direct(header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);

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

static __noinline void emit_bpf_prog_load_debug_enter_fragment_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 attr_ptr = ctx->args[1];
    u64 attr_size = ctx->args[2];
    u32 payload_capacity = BPF_DIRECT_PROG_LOAD_DEBUG_CAPACITY;
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

    u16 flags = EVENT_FLAG_ENTER_FRAGMENT;
    u32 payload_size = capture_bpf_prog_load_debug_nested_tlv_direct(
        &ptr,
        payload_offset,
        attr_ptr,
        attr_size,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header *header = event_v2_header_from_dynptr_direct(&ptr);
    if (!header) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    init_syscall_event_v2_header_direct(header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);

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

static __noinline void emit_bpf_uprobe_multi_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    u64 attr_ptr = ctx->args[1];
    u64 attr_size = ctx->args[2];
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_ATTR_MAX + BPF_DIRECT_UPROBE_MULTI_CAPACITY;
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
    u32 payload_size = capture_bpf_attr_tlv_direct(&ptr, payload_offset, attr_ptr, attr_size, &flags);
    payload_size += capture_bpf_uprobe_multi_tlv_direct(
        &ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header *header = event_v2_header_from_dynptr_direct(&ptr);
    if (!header) {
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    init_syscall_event_v2_header_direct(header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);

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
