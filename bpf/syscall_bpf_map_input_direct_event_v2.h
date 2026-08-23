#ifndef STRACE_GO_SYSCALL_BPF_MAP_INPUT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MAP_INPUT_DIRECT_EVENT_V2_H

#define BPF_DIRECT_MAP_UPDATE_ELEM 2
#define BPF_DIRECT_MAP_UPDATE_KEY_IN_ARG 126
#define BPF_DIRECT_MAP_UPDATE_VALUE_IN_ARG 127

struct bpf_map_batch_input_requests {
    struct bpf_nested_bytes_capture_request keys;
    struct bpf_nested_bytes_capture_request values;
};

struct bpf_map_elem_input_requests {
    struct bpf_nested_bytes_capture_request key;
    struct bpf_nested_bytes_capture_request value;
};

static __always_inline void set_bpf_map_input_request_direct(
    struct bpf_nested_bytes_capture_request *request,
    u64 user_ptr,
    u32 user_len,
    u16 arg_index,
    u16 *event_flags)
{
    if (!user_ptr || user_len == 0) {
        return;
    }
    request->user_ptr = user_ptr;
    request->user_len = user_len;
    request->max_len = BPF_DIRECT_MAP_VALUE_MAX;
    request->storage_len = BPF_DIRECT_BYTES_BUCKET_512;
    request->arg_index = arg_index;
    request->event_flags = event_flags;
}

static __always_inline int read_bpf_map_batch_input_requests_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_map_batch_input_requests *requests,
    u16 *event_flags)
{
    u32 map_fd = 0;
    u32 count = 0;
    u64 keys = 0;
    u64 values = 0;
    u64 elem_flags = 0;
    if (!bpf_attr_read_u64_direct(
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
    set_bpf_map_input_request_direct(
        &requests->keys,
        keys,
        bpf_map_batch_buffer_len_direct(count, key_size),
        BPF_DIRECT_MAP_BATCH_KEYS_IN_ARG,
        event_flags);
    set_bpf_map_input_request_direct(
        &requests->values,
        values,
        bpf_map_batch_buffer_len_direct(count, effective_value_size),
        BPF_DIRECT_MAP_BATCH_VALUES_IN_ARG,
        event_flags);
    return requests->keys.user_ptr || requests->values.user_ptr;
}

static __always_inline u32 capture_bpf_map_batch_inputs_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_map_batch_input_requests *requests)
{
    u32 payload_size = 0;
    payload_size += capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->keys);
    payload_size += capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->values);
    return payload_size;
}

static __always_inline u32 capture_bpf_map_batch_input_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    struct bpf_map_batch_input_requests requests = {};
    if (!read_bpf_map_batch_input_requests_direct(
            attr_ptr,
            attr_size,
            &requests,
            event_flags)) {
        return 0;
    }
    return capture_bpf_map_batch_inputs_tlv_direct(
        ptr,
        payload_offset,
        &requests);
}

static __always_inline int read_bpf_map_update_elem_input_requests_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_map_elem_input_requests *requests,
    u16 *event_flags)
{
    u32 map_fd = 0;
    u64 key = 0;
    u64 value = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_FD_OFF, &map_fd) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_KEY_OFF, &key) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_VALUE_OFF, &value)) {
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
        0);
    if (key_size == 0 || effective_value_size == 0) {
        return 0;
    }
    set_bpf_map_input_request_direct(
        &requests->key,
        key,
        key_size,
        BPF_DIRECT_MAP_UPDATE_KEY_IN_ARG,
        event_flags);
    set_bpf_map_input_request_direct(
        &requests->value,
        value,
        effective_value_size,
        BPF_DIRECT_MAP_UPDATE_VALUE_IN_ARG,
        event_flags);
    return requests->key.user_ptr || requests->value.user_ptr;
}

static __always_inline u32 capture_bpf_map_update_elem_inputs_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_map_elem_input_requests *requests)
{
    u32 payload_size = 0;
    payload_size += capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->key);
    payload_size += capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &requests->value);
    return payload_size;
}

#endif
