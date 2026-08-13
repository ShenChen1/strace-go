#ifndef STRACE_GO_SYSCALL_BPF_NESTED_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_NESTED_DIRECT_EVENT_V2_H

#define BPF_DIRECT_LICENSE_MAX 64
#define BPF_DIRECT_INSNS_MAX 64
#define BPF_DIRECT_LOG_BUF_MAX 256
#define BPF_DIRECT_SIGNATURE_MAX 256
#define BPF_DIRECT_OBJ_PATH_MAX 512
#define BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX 512
#define BPF_DIRECT_BTF_MAX 256
#define BPF_DIRECT_LINK_ITER_INFO_MAX 20
#define BPF_DIRECT_STREAM_BUF_MAX 512
#define BPF_DIRECT_KPROBE_MULTI_MAX_ENTRIES 4
#define BPF_DIRECT_KPROBE_SYM_DATA_MAX 40
#define BPF_DIRECT_KPROBE_SYM_RECORD_SIZE (8 + 4 + BPF_DIRECT_KPROBE_SYM_DATA_MAX)
#define BPF_DIRECT_KPROBE_SYMS_MAX (BPF_DIRECT_KPROBE_MULTI_MAX_ENTRIES * BPF_DIRECT_KPROBE_SYM_RECORD_SIZE)
#define BPF_DIRECT_KPROBE_U64_ARRAY_MAX (BPF_DIRECT_KPROBE_MULTI_MAX_ENTRIES * 8)
#define BPF_DIRECT_KPROBE_MULTI_COUNT_LIMIT 1024
#define BPF_DIRECT_PROG_LOAD 5
#define BPF_DIRECT_OBJ_PIN 6
#define BPF_DIRECT_OBJ_GET 7
#define BPF_DIRECT_RAW_TRACEPOINT_OPEN 17
#define BPF_DIRECT_BTF_LOAD 18
#define BPF_DIRECT_LINK_CREATE 28
#define BPF_DIRECT_PROG_STREAM_READ_BY_FD 37
#define BPF_DIRECT_TRACE_ITER_ATTACH 28
#define BPF_DIRECT_TRACE_KPROBE_MULTI_ATTACH 42
#define BPF_DIRECT_PROG_LOAD_LICENSE_ARG 101
#define BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG 102
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_ARG 103
#define BPF_DIRECT_PROG_LOAD_INSNS_ARG 112
#define BPF_DIRECT_OBJ_PATHNAME_ARG 104
#define BPF_DIRECT_RAW_TRACEPOINT_NAME_ARG 105
#define BPF_DIRECT_BTF_ARG 106
#define BPF_DIRECT_LINK_ITER_INFO_ARG 107
#define BPF_DIRECT_KPROBE_MULTI_SYMS_ARG 108
#define BPF_DIRECT_KPROBE_MULTI_ADDRS_ARG 109
#define BPF_DIRECT_KPROBE_MULTI_COOKIES_ARG 110
#define BPF_DIRECT_PROG_STREAM_BUF_ARG 111
#define BPF_DIRECT_PROG_LOAD_LICENSE_OFF 16
#define BPF_DIRECT_PROG_LOAD_INSN_CNT_OFF 4
#define BPF_DIRECT_PROG_LOAD_INSNS_OFF 8
#define BPF_DIRECT_PROG_LOAD_LOG_SIZE_OFF 28
#define BPF_DIRECT_PROG_LOAD_LOG_BUF_OFF 32
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_OFF 152
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_SIZE_OFF 160
#define BPF_DIRECT_BTF_SIZE_OFF 16
#define BPF_DIRECT_PROG_STREAM_BUF_OFF 0
#define BPF_DIRECT_PROG_STREAM_BUF_LEN_OFF 8
#define BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF 8
#define BPF_DIRECT_LINK_CREATE_ITER_INFO_OFF 16
#define BPF_DIRECT_LINK_CREATE_ITER_INFO_LEN_OFF 24
#define BPF_DIRECT_LINK_CREATE_KPROBE_CNT_OFF 20
#define BPF_DIRECT_LINK_CREATE_KPROBE_SYMS_OFF 24
#define BPF_DIRECT_LINK_CREATE_KPROBE_ADDRS_OFF 32
#define BPF_DIRECT_LINK_CREATE_KPROBE_COOKIES_OFF 40
#define BPF_DIRECT_NESTED_CAPACITY \
    (12 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_LICENSE_MAX + BPF_DIRECT_INSNS_MAX + BPF_DIRECT_LOG_BUF_MAX + BPF_DIRECT_SIGNATURE_MAX + BPF_DIRECT_OBJ_PATH_MAX + BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX + BPF_DIRECT_BTF_MAX + BPF_DIRECT_LINK_ITER_INFO_MAX + BPF_DIRECT_STREAM_BUF_MAX + BPF_DIRECT_KPROBE_SYMS_MAX + 2 * BPF_DIRECT_KPROBE_U64_ARRAY_MAX)

static __always_inline int bpf_attr_read_u32_direct(u64 attr_ptr, u64 requested_len, u32 offset, u32 *value)
{
    *value = 0;
    if (!attr_ptr || requested_len < offset + sizeof(*value)) {
        return 0;
    }
    return bpf_probe_read_user(value, sizeof(*value), (void *)(attr_ptr + offset)) == 0;
}

static __always_inline int bpf_attr_read_u64_direct(u64 attr_ptr, u64 requested_len, u32 offset, u64 *value)
{
    *value = 0;
    if (!attr_ptr || requested_len < offset + sizeof(*value)) {
        return 0;
    }
    return bpf_probe_read_user(value, sizeof(*value), (void *)(attr_ptr + offset)) == 0;
}

#include "syscall_bpf_nested_capture_direct_event_v2.h"
#include "syscall_bpf_kprobe_multi_direct_event_v2.h"

static __always_inline u32 capture_bpf_prog_load_insns_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 insns,
    u32 insn_cnt,
    u16 *event_flags)
{
    if (!insns || insn_cnt == 0) {
        return 0;
    }
    if (insn_cnt > 0x1fffffffU) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = insns,
        .user_len = insn_cnt * 8,
        .max_len = BPF_DIRECT_INSNS_MAX,
        .arg_index = BPF_DIRECT_PROG_LOAD_INSNS_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __always_inline u32 capture_bpf_prog_load_nested_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 payload_size = 0;
    u32 insn_cnt = 0;
    u64 insns = 0;
    if (bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_INSN_CNT_OFF, &insn_cnt) &&
        bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_INSNS_OFF, &insns)) {
        payload_size += capture_bpf_prog_load_insns_tlv_direct(
            ptr,
            payload_offset + payload_size,
            insns,
            insn_cnt,
            event_flags);
    }

    u64 license_ptr = 0;
    if (bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_LICENSE_OFF, &license_ptr)) {
        payload_size += capture_bpf_license_tlv_direct(ptr, payload_offset + payload_size, license_ptr);
    }

    u32 log_size = 0;
    u64 log_buf = 0;
    if (bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_LOG_SIZE_OFF, &log_size) &&
        bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_LOG_BUF_OFF, &log_buf)) {
        struct bpf_nested_bytes_capture_request request = {
            .user_ptr = log_buf,
            .user_len = log_size,
            .max_len = BPF_DIRECT_LOG_BUF_MAX,
            .arg_index = BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG,
            .event_flags = event_flags,
        };
        payload_size += capture_bpf_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request);
    }

    u32 signature_size = 0;
    u64 signature = 0;
    if (bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_SIGNATURE_SIZE_OFF, &signature_size) &&
        bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_SIGNATURE_OFF, &signature)) {
        struct bpf_nested_bytes_capture_request request = {
            .user_ptr = signature,
            .user_len = signature_size,
            .max_len = BPF_DIRECT_SIGNATURE_MAX,
            .arg_index = BPF_DIRECT_PROG_LOAD_SIGNATURE_ARG,
            .event_flags = event_flags,
        };
        payload_size += capture_bpf_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request);
    }
    return payload_size;
}

static __always_inline u32 capture_bpf_obj_pathname_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size)
{
    u64 pathname = 0;
    if (!bpf_attr_read_u64_direct(attr_ptr, attr_size, 0, &pathname) || !pathname) {
        return 0;
    }
    return capture_bpf_string_tlv_direct(
        ptr,
        payload_offset,
        pathname,
        BPF_DIRECT_OBJ_PATH_MAX,
        BPF_DIRECT_OBJ_PATHNAME_ARG);
}

static __always_inline u32 capture_bpf_raw_tracepoint_name_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size)
{
    u64 name = 0;
    if (!bpf_attr_read_u64_direct(attr_ptr, attr_size, 0, &name) || !name) {
        return 0;
    }
    return capture_bpf_string_tlv_direct(
        ptr,
        payload_offset,
        name,
        BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX,
        BPF_DIRECT_RAW_TRACEPOINT_NAME_ARG);
}

static __always_inline u32 capture_bpf_btf_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 btf = 0;
    u32 btf_size = 0;
    if (!bpf_attr_read_u64_direct(attr_ptr, attr_size, 0, &btf) ||
        !bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_BTF_SIZE_OFF, &btf_size) ||
        !btf || btf_size == 0) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = btf,
        .user_len = btf_size,
        .max_len = BPF_DIRECT_BTF_MAX,
        .arg_index = BPF_DIRECT_BTF_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __always_inline u32 capture_bpf_prog_stream_read_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 stream_buf = 0;
    u32 stream_buf_len = 0;
    if (!bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_STREAM_BUF_OFF, &stream_buf) ||
        !bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_STREAM_BUF_LEN_OFF, &stream_buf_len) ||
        !stream_buf || stream_buf_len == 0) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = stream_buf,
        .user_len = stream_buf_len,
        .max_len = BPF_DIRECT_STREAM_BUF_MAX,
        .arg_index = BPF_DIRECT_PROG_STREAM_BUF_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __always_inline u32 capture_bpf_link_iter_info_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 attach_type = 0;
    u64 iter_info = 0;
    u32 iter_info_len = 0;
    if (!bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF, &attach_type) ||
        attach_type != BPF_DIRECT_TRACE_ITER_ATTACH ||
        !bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ITER_INFO_OFF, &iter_info) ||
        !bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_LINK_CREATE_ITER_INFO_LEN_OFF, &iter_info_len) ||
        !iter_info || iter_info_len == 0) {
        return 0;
    }
    if (iter_info_len > 0x3fffffffU) {
        return 0;
    }

    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = iter_info,
        .user_len = iter_info_len * 4,
        .max_len = BPF_DIRECT_LINK_ITER_INFO_MAX,
        .arg_index = BPF_DIRECT_LINK_ITER_INFO_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __always_inline u32 capture_bpf_nested_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 cmd,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (cmd == BPF_DIRECT_PROG_LOAD) {
        payload_size += capture_bpf_prog_load_nested_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
    } else if (cmd == BPF_DIRECT_OBJ_PIN || cmd == BPF_DIRECT_OBJ_GET) {
        payload_size += capture_bpf_obj_pathname_tlv_direct(ptr, payload_offset, attr_ptr, attr_size);
    } else if (cmd == BPF_DIRECT_RAW_TRACEPOINT_OPEN) {
        payload_size += capture_bpf_raw_tracepoint_name_tlv_direct(ptr, payload_offset, attr_ptr, attr_size);
    } else if (cmd == BPF_DIRECT_BTF_LOAD) {
        payload_size += capture_bpf_btf_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
    } else if (cmd == BPF_DIRECT_PROG_STREAM_READ_BY_FD) {
        payload_size += capture_bpf_prog_stream_read_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
    } else if (cmd == BPF_DIRECT_LINK_CREATE) {
        payload_size += capture_bpf_link_iter_info_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
        payload_size += capture_bpf_kprobe_multi_tlv_direct(ptr, payload_offset + payload_size, attr_ptr, attr_size, event_flags);
    }
    return payload_size;
}

#endif
