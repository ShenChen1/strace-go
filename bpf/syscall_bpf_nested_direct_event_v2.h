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

#include "syscall_bpf_kprobe_multi_direct_event_v2.h"

static __always_inline u32 capture_bpf_license_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_LICENSE_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, BPF_DIRECT_LICENSE_MAX, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > BPF_DIRECT_LICENSE_MAX) {
            copied_len = BPF_DIRECT_LICENSE_MAX;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            BPF_DIRECT_PROG_LOAD_LICENSE_ARG,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_bpf_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 user_len,
    u32 max_len,
    u16 arg_index,
    u16 *event_flags)
{
    if (!user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(user_len, max_len);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (max_len == BPF_DIRECT_LOG_BUF_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_LOG_BUF_MAX);
    } else if (max_len == BPF_DIRECT_INSNS_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_INSNS_MAX);
    } else if (max_len == BPF_DIRECT_SIGNATURE_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_SIGNATURE_MAX);
    } else if (max_len == BPF_DIRECT_BTF_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_BTF_MAX);
    } else if (max_len == BPF_DIRECT_STREAM_BUF_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_STREAM_BUF_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_LINK_ITER_INFO_MAX);
    }
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
            arg_index,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_bpf_string_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 max_len,
    u16 arg_index)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (max_len == BPF_DIRECT_OBJ_PATH_MAX) {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_OBJ_PATH_MAX);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX);
    }
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(payload_data, max_len, (void *)user_ptr);
        if (n < 0) {
            probe_ret = n;
        } else if (n > max_len) {
            copied_len = max_len;
        } else {
            copied_len = (u32)n;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            arg_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

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
    return capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset,
        insns,
        insn_cnt * 8,
        BPF_DIRECT_INSNS_MAX,
        BPF_DIRECT_PROG_LOAD_INSNS_ARG,
        event_flags);
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
        payload_size += capture_bpf_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            log_buf,
            log_size,
            BPF_DIRECT_LOG_BUF_MAX,
            BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG,
            event_flags);
    }

    u32 signature_size = 0;
    u64 signature = 0;
    if (bpf_attr_read_u32_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_SIGNATURE_SIZE_OFF, &signature_size) &&
        bpf_attr_read_u64_direct(attr_ptr, attr_size, BPF_DIRECT_PROG_LOAD_SIGNATURE_OFF, &signature)) {
        payload_size += capture_bpf_bytes_tlv_direct(
            ptr,
            payload_offset + payload_size,
            signature,
            signature_size,
            BPF_DIRECT_SIGNATURE_MAX,
            BPF_DIRECT_PROG_LOAD_SIGNATURE_ARG,
            event_flags);
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
    return capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset,
        btf,
        btf_size,
        BPF_DIRECT_BTF_MAX,
        BPF_DIRECT_BTF_ARG,
        event_flags);
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
    return capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset,
        stream_buf,
        stream_buf_len,
        BPF_DIRECT_STREAM_BUF_MAX,
        BPF_DIRECT_PROG_STREAM_BUF_ARG,
        event_flags);
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

    return capture_bpf_bytes_tlv_direct(
        ptr,
        payload_offset,
        iter_info,
        iter_info_len * 4,
        BPF_DIRECT_LINK_ITER_INFO_MAX,
        BPF_DIRECT_LINK_ITER_INFO_ARG,
        event_flags);
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
