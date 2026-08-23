#ifndef STRACE_GO_SYSCALL_BPF_MAP_LOOKUP_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_MAP_LOOKUP_DIRECT_EVENT_V2_H

#define BPF_DIRECT_MAP_LOOKUP_ELEM 1
#define BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_DIRECT_MAP_LOOKUP_KEY_IN_ARG 139

static __always_inline int read_bpf_map_lookup_key_input_request_direct(
    u64 attr_ptr,
    u64 attr_size,
    struct bpf_nested_bytes_capture_request *request,
    u16 *event_flags)
{
    return read_bpf_map_key_input_request_direct(
        attr_ptr,
        attr_size,
        BPF_DIRECT_MAP_LOOKUP_KEY_IN_ARG,
        request,
        event_flags);
}

static __always_inline u32 capture_bpf_map_lookup_key_input_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_nested_bytes_capture_request *request)
{
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, request);
}

#endif
