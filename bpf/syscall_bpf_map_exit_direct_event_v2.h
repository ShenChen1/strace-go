#ifndef STRACE_GO_SYSCALL_BPF_MAP_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MAP_EXIT_DIRECT_EVENT_V2_H

#include "syscall_bpf_map_common_direct_event_v2.h"

#ifndef ENOENT
#define ENOENT 2
#endif

static __always_inline int read_bpf_map_lookup_output_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_exit_bytes_request *request)
{
    u32 map_fd = 0;
    u64 value_ptr = 0;
    u64 elem_flags = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_FD_OFF, &map_fd) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_VALUE_OFF, &value_ptr) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_ELEM_FLAGS_OFF, &elem_flags) ||
        !value_ptr) {
        return 0;
    }

    struct bpf_map *map = lookup_current_bpf_map_direct((s32)map_fd);
    if (!map) {
        return 0;
    }
    u32 value_size = BPF_CORE_READ(map, value_size);
    u32 effective_value_size = bpf_map_effective_value_size_direct(
        map,
        value_size,
        elem_flags);
    if (effective_value_size == 0) {
        return 0;
    }

    request->user_ptr = value_ptr;
    request->user_len = effective_value_size;
    request->max_len = BPF_DIRECT_MAP_VALUE_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = BPF_DIRECT_MAP_VALUE_ARG;
    return 1;
}

static __always_inline int emit_bpf_map_lookup_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) || ret_value != 0 ||
        (p->args[0] != BPF_DIRECT_MAP_LOOKUP_ELEM &&
         p->args[0] != BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM)) {
        return 0;
    }

    struct bpf_exit_bytes_request request = {};
    if (!read_bpf_map_lookup_output_request_direct(
            p->args[1], p->args[2], &request)) {
        return 0;
    }
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

static __always_inline int read_bpf_map_get_next_key_output_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    u32 key_size,
    struct bpf_exit_bytes_request *request)
{
    u64 next_key = 0;
    if (!bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_NEXT_KEY_OFF, &next_key) ||
        !next_key || key_size == 0) {
        return 0;
    }
    request->user_ptr = next_key;
    request->user_len = key_size;
    request->max_len = BPF_DIRECT_MAP_VALUE_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = BPF_DIRECT_MAP_GET_NEXT_KEY_NEXT_OUT_ARG;
    return 1;
}

static __always_inline int emit_bpf_map_get_next_key_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
	if (!is_bpf_direct_syscall(p->sys_id) ||
	    ret_value != 0 ||
	    p->args[0] != BPF_DIRECT_MAP_GET_NEXT_KEY) {
	    return 0;
	}

	u32 key_size = lookup_pending_syscall_aux0(p->tid);
	struct bpf_exit_bytes_request request = {};
	if (!read_bpf_map_get_next_key_output_request_direct(
	        p->args[1], p->args[2], key_size, &request)) {
        return 0;
    }
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

struct bpf_map_batch_output_requests {
    struct bpf_exit_bytes_request out_batch;
    struct bpf_exit_bytes_request keys;
    struct bpf_exit_bytes_request values;
};

static __always_inline u32 bpf_map_batch_cursor_len_direct(
    struct bpf_map *map,
    u32 key_size)
{
    u32 map_type = BPF_CORE_READ(map, map_type);
    if (key_size < BPF_DIRECT_MAP_BATCH_CURSOR_MIN &&
        (map_type == BPF_DIRECT_MAP_TYPE_HASH ||
         map_type == BPF_DIRECT_MAP_TYPE_PERCPU_HASH ||
         map_type == BPF_DIRECT_MAP_TYPE_LRU_HASH ||
         map_type == BPF_DIRECT_MAP_TYPE_LRU_PERCPU_HASH)) {
        return BPF_DIRECT_MAP_BATCH_CURSOR_MIN;
    }
    return key_size;
}

static __always_inline void set_bpf_map_batch_output_request_direct(
    struct bpf_exit_bytes_request *request,
    u64 user_ptr,
    u32 user_len,
    u16 arg_index)
{
    if (!user_ptr || user_len == 0) {
        return;
    }
    request->user_ptr = user_ptr;
    request->user_len = user_len;
    request->max_len = BPF_DIRECT_MAP_VALUE_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = arg_index;
}

static __always_inline int read_bpf_map_batch_output_requests_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_map_batch_output_requests *requests)
{
    u32 map_fd = 0;
    u32 count = 0;
    u64 out_batch = 0;
    u64 keys = 0;
    u64 values = 0;
    u64 elem_flags = 0;
    if (!bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_OUT_BATCH_OFF, &out_batch) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_KEYS_OFF, &keys) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_VALUES_OFF, &values) ||
        !bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_COUNT_OFF, &count) ||
        !bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_FD_OFF, &map_fd) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_ELEM_FLAGS_OFF, &elem_flags) ||
        count == 0) {
        return 0;
    }

    struct bpf_map *map = lookup_current_bpf_map_direct((s32)map_fd);
    if (!map) {
        return 0;
    }
    u32 key_size = BPF_CORE_READ(map, key_size);
    u32 value_size = BPF_CORE_READ(map, value_size);
    u32 effective_value_size = bpf_map_effective_value_size_direct(
        map,
        value_size,
        elem_flags);
    if (effective_value_size == 0) {
        return 0;
    }
    u32 cursor_size = bpf_map_batch_cursor_len_direct(map, key_size);
    set_bpf_map_batch_output_request_direct(
        &requests->out_batch,
        out_batch,
        cursor_size,
        BPF_DIRECT_MAP_BATCH_OUT_BATCH_ARG);
    set_bpf_map_batch_output_request_direct(
        &requests->keys,
        keys,
        bpf_map_batch_buffer_len_direct(count, key_size),
        BPF_DIRECT_MAP_BATCH_KEYS_ARG);
    set_bpf_map_batch_output_request_direct(
        &requests->values,
        values,
        bpf_map_batch_buffer_len_direct(count, effective_value_size),
        BPF_DIRECT_MAP_BATCH_VALUES_ARG);
    return requests->out_batch.user_ptr || requests->keys.user_ptr || requests->values.user_ptr;
}

static __always_inline u32 capture_bpf_map_batch_outputs_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_map_batch_output_requests *requests,
    u16 *event_flags)
{
    u32 payload_size = 0;
    payload_size += capture_bpf_exit_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->out_batch,
        event_flags);
    payload_size += capture_bpf_exit_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->keys,
        event_flags);
    payload_size += capture_bpf_exit_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->values,
        event_flags);
    return payload_size;
}

static __always_inline int emit_bpf_map_batch_lookup_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    // BPF_MAP_LOOKUP_BATCH and BPF_MAP_LOOKUP_AND_DELETE_BATCH share one output path.
    if (!is_bpf_direct_syscall(p->sys_id) ||
        (ret_value != 0 && ret_value != -ENOENT) ||
        (p->args[0] != BPF_DIRECT_MAP_LOOKUP_BATCH &&
         p->args[0] != BPF_DIRECT_MAP_LOOKUP_AND_DELETE_BATCH)) {
        return 0;
    }

    struct bpf_map_batch_output_requests requests = {};
    if (!read_bpf_map_batch_output_requests_direct(
            p->args[1], p->args[2], &requests)) {
        return 0;
    }

    u32 payload_capacity = 3 *
        (PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_MAP_VALUE_MAX);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long reserve_ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (reserve_ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    u16 flags = 0;
    u32 payload_size = capture_bpf_map_batch_outputs_direct(
        &ptr,
        payload_offset,
        &requests,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
    reserve_ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (reserve_ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body, p, ret_value, duration, payload_size);
    reserve_ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (reserve_ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 1;
}

#endif
