#ifndef STRACE_GO_SYSCALL_BPF_KPROBE_MULTI_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_KPROBE_MULTI_DIRECT_EVENT_V2_H

struct bpf_direct_kprobe_sym_record {
    u64 ptr;
    s32 len;
    u8 data[BPF_DIRECT_KPROBE_SYM_DATA_MAX];
} __attribute__((packed));

static __always_inline u32 capture_bpf_kprobe_syms_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 syms,
    u32 count,
    u16 *event_flags)
{
    if (!syms || count == 0 || count > BPF_DIRECT_MULTI_COUNT_LIMIT) {
        return 0;
    }

    u32 copied_entries = bpf_direct_multi_copy_entries(count);
    u32 copied_len = copied_entries * BPF_DIRECT_KPROBE_SYM_RECORD_SIZE;
    u32 user_len = bpf_direct_multi_user_len(count, BPF_DIRECT_KPROBE_SYM_RECORD_SIZE);
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

#pragma unroll
    for (int i = 0; i < BPF_DIRECT_KPROBE_MULTI_MAX_ENTRIES; i++) {
        if ((u32)i < copied_entries) {
            struct bpf_direct_kprobe_sym_record record = {};
            u64 sym_ptr = 0;
            long err = bpf_probe_read_user(&sym_ptr, sizeof(sym_ptr), (void *)(syms + (u64)i * sizeof(u64)));
            if (err < 0) {
                record.len = (s32)err;
            } else {
                record.ptr = sym_ptr;
                if (sym_ptr) {
                    long n = bpf_probe_read_user_str(record.data, BPF_DIRECT_KPROBE_SYM_DATA_MAX, (void *)sym_ptr);
                    record.len = (s32)n;
                }
            }
            err = bpf_dynptr_write(
                ptr,
                data_offset + (u32)i * BPF_DIRECT_KPROBE_SYM_RECORD_SIZE,
                &record,
                sizeof(record),
                0);
            if (err < 0) {
                record_ringbuf_copy_fail();
                return 0;
            }
        }
    }

    if (copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            BPF_DIRECT_KPROBE_MULTI_SYMS_ARG,
            0,
            user_len,
            copied_len,
            0,
            syms)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_bpf_kprobe_multi_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 attach_type = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF, &attach_type) ||
        attach_type != BPF_DIRECT_TRACE_KPROBE_MULTI_ATTACH) {
        return 0;
    }

    u32 count = 0;
    u64 syms = 0;
    u64 addrs = 0;
    u64 cookies = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_KPROBE_CNT_OFF, &count) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_KPROBE_SYMS_OFF, &syms) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_KPROBE_ADDRS_OFF, &addrs) ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_KPROBE_COOKIES_OFF, &cookies)) {
        return 0;
    }

    u32 payload_size = 0;
    payload_size += capture_bpf_kprobe_syms_tlv_direct(ptr, payload_offset + payload_size, syms, count, event_flags);
    struct bpf_multi_u64_array_capture_request addrs_request = {
        .user_ptr = addrs,
        .count = count,
        .arg_index = BPF_DIRECT_KPROBE_MULTI_ADDRS_ARG,
        .event_flags = event_flags,
    };
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &addrs_request);
    struct bpf_multi_u64_array_capture_request cookies_request = {
        .user_ptr = cookies,
        .count = count,
        .arg_index = BPF_DIRECT_KPROBE_MULTI_COOKIES_ARG,
        .event_flags = event_flags,
    };
    payload_size += capture_bpf_multi_u64_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        &cookies_request);
    return payload_size;
}

#endif
