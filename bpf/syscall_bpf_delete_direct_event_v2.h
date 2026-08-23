#ifndef STRACE_GO_SYSCALL_BPF_DELETE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_DELETE_DIRECT_EVENT_V2_H

static __always_inline int read_bpf_map_delete_batch_input_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_nested_bytes_capture_request *request,
    u16 *event_flags)
{
    u32 map_fd = 0;
    u32 count = 0;
    u64 keys = 0;
    if (!bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_KEYS_OFF, &keys) ||
        !bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_COUNT_OFF, &count) ||
        !bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_BATCH_FD_OFF, &map_fd) ||
        count == 0) {
        return 0;
    }

    struct bpf_map *map = lookup_current_bpf_map_direct((s32)map_fd);
    if (!map) {
        return 0;
    }
    u32 key_size = BPF_CORE_READ(map, key_size);
    set_bpf_map_input_request_direct(
        request,
        keys,
        bpf_map_batch_buffer_len_direct(count, key_size),
        BPF_DIRECT_MAP_BATCH_KEYS_IN_ARG,
        event_flags);
    return request->user_ptr != 0;
}

static __always_inline int read_bpf_map_delete_elem_input_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_nested_bytes_capture_request *request,
    u16 *event_flags)
{
    return read_bpf_map_key_input_request_direct(
        attr_ptr,
        attr_size,
        BPF_DIRECT_MAP_DELETE_KEY_IN_ARG,
        request,
        event_flags);
}

static __always_inline u32 capture_bpf_map_delete_batch_input_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_nested_bytes_capture_request *request)
{
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, request);
}

static __always_inline u32 capture_bpf_map_delete_elem_input_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_nested_bytes_capture_request *request)
{
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, request);
}

#endif
