#ifndef STRACE_GO_SYSCALL_BPF_UPROBE_MULTI_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_UPROBE_MULTI_DIRECT_EVENT_V2_H

#define BPF_DIRECT_UPROBE_MULTI_CAPACITY \
    (4 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_UPROBE_MULTI_PATH_MAX + 3 * BPF_DIRECT_MULTI_U64_ARRAY_MAX)

static __always_inline int is_bpf_uprobe_multi_enter_direct(
    struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->args[0] != BPF_DIRECT_LINK_CREATE) {
        return 0;
    }
    u32 attach_type = 0;
    if (!bpf_attr_read_u32_direct(
            ctx->args[1],
            ctx->args[2],
            BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF,
            &attach_type)) {
        return 0;
    }
    return attach_type == BPF_DIRECT_TRACE_UPROBE_MULTI_ATTACH;
}

static __always_inline u32 capture_bpf_uprobe_multi_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size)
{
    u64 path = 0;
    if (!bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_UPROBE_PATH_OFF, &path) || !path) {
        return 0;
    }
    return capture_bpf_string_tlv_direct(
        ptr,
        payload_offset,
        path,
        BPF_DIRECT_UPROBE_MULTI_PATH_MAX,
        BPF_DIRECT_UPROBE_MULTI_PATH_ARG);
}

static __noinline u32 capture_bpf_uprobe_multi_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 attach_type = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF, &attach_type) ||
        attach_type != BPF_DIRECT_TRACE_UPROBE_MULTI_ATTACH) {
        return 0;
    }

    u32 count = 0;
    u64 offsets = 0;
    u64 ref_ctr_offsets = 0;
    u64 cookies = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_UPROBE_CNT_OFF, &count) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_UPROBE_OFFSETS_OFF, &offsets) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_UPROBE_REF_CTR_OFFSETS_OFF, &ref_ctr_offsets) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_UPROBE_COOKIES_OFF, &cookies)) {
        return 0;
    }

    u32 payload_size = capture_bpf_uprobe_multi_path_tlv_direct(
        ptr,
        payload_offset,
        attr_ptr,
        attr_size);
    struct bpf_multi_u64_array_capture_request offsets_request = {
        .user_ptr = offsets,
        .count = count,
        .arg_index = BPF_DIRECT_UPROBE_MULTI_OFFSETS_ARG,
        .event_flags = event_flags,
    };
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &offsets_request);
    struct bpf_multi_u64_array_capture_request ref_request = {
        .user_ptr = ref_ctr_offsets,
        .count = count,
        .arg_index = BPF_DIRECT_UPROBE_MULTI_REF_CTR_OFFSETS_ARG,
        .event_flags = event_flags,
    };
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &ref_request);
    struct bpf_multi_u64_array_capture_request cookies_request = {
        .user_ptr = cookies,
        .count = count,
        .arg_index = BPF_DIRECT_UPROBE_MULTI_COOKIES_ARG,
        .event_flags = event_flags,
    };
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &cookies_request);
    return payload_size;
}

#endif
