#ifndef STRACE_GO_SYSCALL_BPF_MAP_KEY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MAP_KEY_DIRECT_EVENT_V2_H

static __always_inline int read_bpf_map_key_input_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    u16 arg_index,
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

    struct bpf_map *map = lookup_current_bpf_map_direct((s32)map_fd);
    if (!map) {
        return 0;
    }
    u32 key_size = BPF_CORE_READ(map, key_size);
    set_bpf_map_input_request_direct(
        request,
        key,
        key_size,
        arg_index,
        event_flags);
    return request->user_ptr != 0;
}

#endif
