#ifndef STRACE_GO_SYSCALL_BPF_NESTED_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_NESTED_DIRECT_EVENT_V2_H

#include "syscall_bpf_map_common_direct_event_v2.h"

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
#define BPF_DIRECT_MULTI_MAX_ENTRIES 4
#define BPF_DIRECT_MULTI_U32_ARRAY_MAX (BPF_DIRECT_MULTI_MAX_ENTRIES * 4)
#define BPF_DIRECT_MULTI_U64_ARRAY_MAX (BPF_DIRECT_MULTI_MAX_ENTRIES * 8)
#define BPF_DIRECT_MULTI_COUNT_LIMIT 1024
#define BPF_DIRECT_MAP_LOOKUP_ELEM 1
#define BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_DIRECT_MAP_DELETE_ELEM 3
#define BPF_DIRECT_MAP_GET_NEXT_KEY 4
#define BPF_DIRECT_MAP_LOOKUP_BATCH 24
#define BPF_DIRECT_MAP_LOOKUP_AND_DELETE_BATCH 25
#define BPF_DIRECT_MAP_UPDATE_BATCH 26
#define BPF_DIRECT_MAP_DELETE_BATCH 27
#define BPF_DIRECT_PROG_LOAD 5
#define BPF_DIRECT_PROG_TEST_RUN 10
#define BPF_DIRECT_PROG_QUERY 16
#define BPF_DIRECT_OBJ_PIN 6
#define BPF_DIRECT_OBJ_GET 7
#define BPF_DIRECT_RAW_TRACEPOINT_OPEN 17
#define BPF_DIRECT_BTF_LOAD 18
#define BPF_DIRECT_LINK_CREATE 28
#define BPF_DIRECT_PROG_STREAM_READ_BY_FD 37
#define BPF_DIRECT_TRACE_ITER_ATTACH 28
#define BPF_DIRECT_TRACE_KPROBE_MULTI_ATTACH 42
#define BPF_DIRECT_TRACE_FENTRY_MULTI_ATTACH 59
#define BPF_DIRECT_TRACE_FEXIT_MULTI_ATTACH 60
#define BPF_DIRECT_TRACE_FSESSION_MULTI_ATTACH 61
#define BPF_DIRECT_PROG_LOAD_LICENSE_ARG 101
#define BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG 102
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_ARG 103
#define BPF_DIRECT_PROG_LOAD_INSNS_ARG 112
#define BPF_DIRECT_PROG_LOAD_FD_ARRAY_ARG 141
#define BPF_DIRECT_PROG_LOAD_FUNC_INFO_ARG 142
#define BPF_DIRECT_PROG_LOAD_LINE_INFO_ARG 143
#define BPF_DIRECT_PROG_LOAD_CORE_RELOS_ARG 144
#define BPF_DIRECT_OBJ_PATHNAME_ARG 104
#define BPF_DIRECT_RAW_TRACEPOINT_NAME_ARG 105
#define BPF_DIRECT_BTF_ARG 106
#define BPF_DIRECT_BTF_LOG_BUF_ARG 114
#define BPF_DIRECT_TEST_RUN_DATA_ARG 115
#define BPF_DIRECT_TEST_RUN_CTX_ARG 116
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
#define BPF_DIRECT_PROG_LOAD_LOG_TRUE_SIZE_OFF 140
#define BPF_DIRECT_PROG_LOAD_LOG_MAX 256
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_OFF 152
#define BPF_DIRECT_PROG_LOAD_SIGNATURE_SIZE_OFF 160
#define BPF_DIRECT_PROG_LOAD_FD_ARRAY_OFF 120
#define BPF_DIRECT_PROG_LOAD_FD_ARRAY_CNT_OFF 148
#define BPF_DIRECT_PROG_LOAD_FD_ARRAY_MAX 512
#define BPF_DIRECT_PROG_LOAD_FUNC_INFO_REC_SIZE_OFF 76
#define BPF_DIRECT_PROG_LOAD_FUNC_INFO_OFF 80
#define BPF_DIRECT_PROG_LOAD_FUNC_INFO_CNT_OFF 88
#define BPF_DIRECT_PROG_LOAD_FUNC_INFO_MAX 512
#define BPF_DIRECT_PROG_LOAD_LINE_INFO_REC_SIZE_OFF 92
#define BPF_DIRECT_PROG_LOAD_LINE_INFO_OFF 96
#define BPF_DIRECT_PROG_LOAD_LINE_INFO_CNT_OFF 104
#define BPF_DIRECT_PROG_LOAD_LINE_INFO_MAX 512
#define BPF_DIRECT_PROG_LOAD_CORE_RELO_CNT_OFF 116
#define BPF_DIRECT_PROG_LOAD_CORE_RELOS_OFF 128
#define BPF_DIRECT_PROG_LOAD_CORE_RELO_REC_SIZE_OFF 136
#define BPF_DIRECT_PROG_LOAD_CORE_RELOS_MAX 512
#define BPF_DIRECT_BTF_SIZE_OFF 16
#define BPF_DIRECT_BTF_LOG_BUF_OFF 8
#define BPF_DIRECT_BTF_LOG_SIZE_OFF 20
#define BPF_DIRECT_BTF_LOG_TRUE_SIZE_OFF 28
#define BPF_DIRECT_BTF_LOG_MAX 256
#define BPF_DIRECT_MAP_FD_OFF 0
#define BPF_DIRECT_MAP_KEY_OFF 8
#define BPF_DIRECT_MAP_VALUE_OFF 16
#define BPF_DIRECT_MAP_VALUE_ARG 117
#define BPF_DIRECT_MAP_VALUE_MAX 512
#define BPF_DIRECT_BYTES_BUCKET_20 BPF_DIRECT_LINK_ITER_INFO_MAX
#define BPF_DIRECT_BYTES_BUCKET_64 BPF_DIRECT_INSNS_MAX
#define BPF_DIRECT_BYTES_BUCKET_256 BPF_DIRECT_LOG_BUF_MAX
#define BPF_DIRECT_BYTES_BUCKET_512 BPF_DIRECT_MAP_VALUE_MAX
#define BPF_DIRECT_MAP_BATCH_OUT_BATCH_OFF 8
#define BPF_DIRECT_MAP_BATCH_KEYS_OFF 16
#define BPF_DIRECT_MAP_BATCH_VALUES_OFF 24
#define BPF_DIRECT_MAP_BATCH_COUNT_OFF 32
#define BPF_DIRECT_MAP_BATCH_FD_OFF 36
#define BPF_DIRECT_MAP_BATCH_ELEM_FLAGS_OFF 40
#define BPF_DIRECT_MAP_ELEM_FLAGS_OFF 24
#define BPF_DIRECT_MAP_BATCH_OUT_BATCH_ARG 120
#define BPF_DIRECT_MAP_BATCH_KEYS_ARG 118
#define BPF_DIRECT_MAP_BATCH_VALUES_ARG 119
#define BPF_DIRECT_MAP_BATCH_KEYS_IN_ARG 121
#define BPF_DIRECT_MAP_BATCH_VALUES_IN_ARG 122
#define BPF_DIRECT_MAP_DELETE_KEY_IN_ARG 123
#define BPF_DIRECT_MAP_GET_NEXT_KEY_KEY_IN_ARG 124
#define BPF_DIRECT_MAP_GET_NEXT_KEY_NEXT_OUT_ARG 125
#define BPF_DIRECT_PROG_QUERY_PROG_IDS_ARG 128
#define BPF_DIRECT_PROG_QUERY_PROG_ATTACH_FLAGS_ARG 129
#define BPF_DIRECT_PROG_QUERY_LINK_IDS_ARG 130
#define BPF_DIRECT_PROG_QUERY_LINK_ATTACH_FLAGS_ARG 131
#define BPF_DIRECT_PROG_QUERY_PROG_CNT_OUT_ARG 132
#define BPF_DIRECT_MAP_NEXT_KEY_OFF 16
#define BPF_DIRECT_TEST_RUN_DATA_SIZE_OUT_OFF 12
#define BPF_DIRECT_TEST_RUN_DATA_OUT_OFF 24
#define BPF_DIRECT_TEST_RUN_CTX_SIZE_OUT_OFF 44
#define BPF_DIRECT_TEST_RUN_CTX_OUT_OFF 56
#define BPF_DIRECT_TEST_RUN_OUTPUT_MAX 512
#define BPF_DIRECT_PROG_QUERY_PROG_IDS_OFF 16
#define BPF_DIRECT_PROG_QUERY_PROG_CNT_OFF 24
#define BPF_DIRECT_PROG_QUERY_PROG_ATTACH_FLAGS_OFF 32
#define BPF_DIRECT_PROG_QUERY_LINK_IDS_OFF 40
#define BPF_DIRECT_PROG_QUERY_LINK_ATTACH_FLAGS_OFF 48
#define BPF_DIRECT_PROG_QUERY_ARRAY_MAX 512
#define BPF_DIRECT_PROG_STREAM_BUF_OFF 0
#define BPF_DIRECT_PROG_STREAM_BUF_LEN_OFF 8
#define BPF_DIRECT_LINK_CREATE_ATTACH_TYPE_OFF 8
#define BPF_DIRECT_LINK_CREATE_ITER_INFO_OFF 16
#define BPF_DIRECT_LINK_CREATE_ITER_INFO_LEN_OFF 24
#define BPF_DIRECT_LINK_CREATE_KPROBE_CNT_OFF 20
#define BPF_DIRECT_LINK_CREATE_KPROBE_SYMS_OFF 24
#define BPF_DIRECT_LINK_CREATE_KPROBE_ADDRS_OFF 32
#define BPF_DIRECT_LINK_CREATE_KPROBE_COOKIES_OFF 40
#define BPF_DIRECT_LINK_CREATE_TRACING_MULTI_IDS_OFF 16
#define BPF_DIRECT_LINK_CREATE_TRACING_MULTI_COOKIES_OFF 24
#define BPF_DIRECT_LINK_CREATE_TRACING_MULTI_CNT_OFF 32
#define BPF_DIRECT_TRACE_UPROBE_MULTI_ATTACH 48
#define BPF_DIRECT_UPROBE_MULTI_PATH_MAX BPF_DIRECT_OBJ_PATH_MAX
#define BPF_DIRECT_UPROBE_MULTI_PATH_ARG 133
#define BPF_DIRECT_UPROBE_MULTI_OFFSETS_ARG 134
#define BPF_DIRECT_UPROBE_MULTI_REF_CTR_OFFSETS_ARG 135
#define BPF_DIRECT_UPROBE_MULTI_COOKIES_ARG 136
#define BPF_DIRECT_TRACING_MULTI_IDS_ARG 145
#define BPF_DIRECT_TRACING_MULTI_COOKIES_ARG 146
#define BPF_DIRECT_LINK_CREATE_UPROBE_PATH_OFF 16
#define BPF_DIRECT_LINK_CREATE_UPROBE_OFFSETS_OFF 24
#define BPF_DIRECT_LINK_CREATE_UPROBE_REF_CTR_OFFSETS_OFF 32
#define BPF_DIRECT_LINK_CREATE_UPROBE_COOKIES_OFF 40
#define BPF_DIRECT_LINK_CREATE_UPROBE_CNT_OFF 48
#define BPF_DIRECT_NESTED_CAPACITY \
    (16 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_OBJ_PATH_MAX + BPF_DIRECT_RAW_TRACEPOINT_NAME_MAX + BPF_DIRECT_BTF_MAX + BPF_DIRECT_LINK_ITER_INFO_MAX + BPF_DIRECT_KPROBE_SYMS_MAX + 2 * BPF_DIRECT_MULTI_U64_ARRAY_MAX + 2 * BPF_DIRECT_MAP_VALUE_MAX)

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
#include "syscall_bpf_prog_load_direct_event_v2.h"
#include "syscall_bpf_multi_array_direct_event_v2.h"
#include "syscall_bpf_kprobe_multi_direct_event_v2.h"
#include "syscall_bpf_uprobe_multi_direct_event_v2.h"
#include "syscall_bpf_map_input_direct_event_v2.h"
#include "syscall_bpf_map_key_direct_event_v2.h"
#include "syscall_bpf_map_lookup_direct_event_v2.h"

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
        .storage_len = BPF_DIRECT_BYTES_BUCKET_256,
        .arg_index = BPF_DIRECT_BTF_ARG,
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
        .storage_len = BPF_DIRECT_BYTES_BUCKET_20,
        .arg_index = BPF_DIRECT_LINK_ITER_INFO_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

#include "syscall_bpf_delete_direct_event_v2.h"
#include "syscall_bpf_get_next_key_direct_event_v2.h"

static __always_inline u32 capture_bpf_nested_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 cmd,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 payload_size = 0;
    if (cmd == BPF_DIRECT_OBJ_PIN || cmd == BPF_DIRECT_OBJ_GET) {
        payload_size += capture_bpf_obj_pathname_tlv_direct(ptr, payload_offset, attr_ptr, attr_size);
    } else if (cmd == BPF_DIRECT_RAW_TRACEPOINT_OPEN) {
        payload_size += capture_bpf_raw_tracepoint_name_tlv_direct(ptr, payload_offset, attr_ptr, attr_size);
    } else if (cmd == BPF_DIRECT_BTF_LOAD) {
        payload_size += capture_bpf_btf_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
    } else if (cmd == BPF_DIRECT_LINK_CREATE) {
        payload_size += capture_bpf_link_iter_info_tlv_direct(ptr, payload_offset, attr_ptr, attr_size, event_flags);
        payload_size += capture_bpf_kprobe_multi_tlv_direct(ptr, payload_offset + payload_size, attr_ptr, attr_size, event_flags);
    } else if (cmd == BPF_DIRECT_MAP_GET_NEXT_KEY) {
        struct bpf_nested_bytes_capture_request request = {};
        if (read_bpf_map_get_next_key_input_request_direct(
                attr_ptr,
                attr_size,
                &request,
                event_flags)) {
            payload_size += capture_bpf_bytes_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &request);
        }
    } else if (cmd == BPF_DIRECT_MAP_LOOKUP_ELEM ||
               cmd == BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM) {
        struct bpf_nested_bytes_capture_request request = {};
        if (read_bpf_map_lookup_key_input_request_direct(
                attr_ptr,
                attr_size,
                &request,
                event_flags)) {
            payload_size += capture_bpf_map_lookup_key_input_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &request);
        }
    } else if (cmd == BPF_DIRECT_MAP_UPDATE_ELEM) {
        struct bpf_map_elem_input_requests requests = {};
        if (read_bpf_map_update_elem_input_requests_direct(
                attr_ptr,
                attr_size,
                &requests,
                event_flags)) {
            payload_size += capture_bpf_map_update_elem_inputs_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &requests);
        }
    } else if (cmd == BPF_DIRECT_MAP_UPDATE_BATCH) {
        payload_size += capture_bpf_map_batch_input_tlv_direct(
            ptr,
            payload_offset + payload_size,
            attr_ptr,
            attr_size,
            event_flags);
    } else if (cmd == BPF_DIRECT_MAP_DELETE_BATCH) {
        struct bpf_nested_bytes_capture_request request = {};
        if (read_bpf_map_delete_batch_input_request_direct(
                attr_ptr,
                attr_size,
                &request,
                event_flags)) {
            payload_size += capture_bpf_map_delete_batch_input_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &request);
        }
    } else if (cmd == BPF_DIRECT_MAP_DELETE_ELEM) {
        struct bpf_nested_bytes_capture_request request = {};
        if (read_bpf_map_delete_elem_input_request_direct(
                attr_ptr,
                attr_size,
                &request,
                event_flags)) {
            payload_size += capture_bpf_map_delete_elem_input_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &request);
        }
    }
    return payload_size;
}

#endif
