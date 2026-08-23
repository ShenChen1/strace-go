#ifndef STRACE_GO_SYSCALL_BPF_GET_NEXT_KEY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_GET_NEXT_KEY_DIRECT_EVENT_V2_H

static __always_inline u32 bpf_map_get_next_key_key_size_direct(
    u64 attr_ptr,
    u64 attr_size)
{
    u32 map_fd = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_FD_OFF, &map_fd)) {
        return 0;
    }
    struct bpf_map *map = lookup_current_bpf_map_direct((s32)map_fd);
    if (!map) {
        return 0;
    }
    return BPF_CORE_READ(map, key_size);
}

static __always_inline int read_bpf_map_get_next_key_input_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_nested_bytes_capture_request *request,
    u16 *event_flags)
{
    u32 map_fd = 0;
    u64 key = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_FD_OFF, &map_fd) ||
        !bpf_attr_read_u64_direct(
            attr_ptr, attr_size, BPF_DIRECT_MAP_KEY_OFF, &key) ||
        !key) {
        return 0;
    }

    u32 key_size = bpf_map_get_next_key_key_size_direct(attr_ptr, attr_size);
    if (key_size == 0) {
        return 0;
    }
    set_bpf_map_input_request_direct(
        request,
        key,
        key_size,
        BPF_DIRECT_MAP_GET_NEXT_KEY_KEY_IN_ARG,
        event_flags);
    return request->user_ptr != 0;
}

#endif
