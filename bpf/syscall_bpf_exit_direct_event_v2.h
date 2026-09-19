#ifndef STRACE_GO_SYSCALL_BPF_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_EXIT_DIRECT_EVENT_V2_H

#define BPF_DIRECT_OBJ_GET_INFO_BY_FD 15
#define BPF_DIRECT_OBJ_INFO_ARG 113
#define BPF_DIRECT_OBJ_INFO_MAX 512
#define BPF_DIRECT_OBJ_INFO_LEN_OFF 4
#define BPF_DIRECT_OBJ_INFO_PTR_OFF 8

struct bpf_exit_bytes_request {
    u64 user_ptr;
    u32 user_len;
    u32 max_len;
    u32 storage_len;
    u16 arg_index;
};

static __always_inline u32 capture_bpf_exit_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct bpf_exit_bytes_request *request,
    u16 *event_flags)
{
    if (!request->user_ptr || request->user_len == 0 ||
        request->max_len == 0 || request->max_len > BPF_DIRECT_OBJ_INFO_MAX ||
        request->storage_len < request->max_len ||
        request->storage_len != BPF_DIRECT_BYTES_BUCKET_512) {
        return 0;
    }

    u32 user_len = payload_tlv_clamp_u32(request->user_len);
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    // The shared writer reserves the 512-byte bucket; keep the dynptr access fixed for verifier range tracking.
    void *payload_data = bpf_dynptr_data(ptr, data_offset, BPF_DIRECT_OBJ_INFO_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(request->user_len, request->max_len);
    asm volatile ("" : "+r"(copied_len));
    if (copied_len > BPF_DIRECT_OBJ_INFO_MAX) {
        copied_len = BPF_DIRECT_OBJ_INFO_MAX;
    }
    long err = bpf_probe_read_user(payload_data, copied_len, (void *)request->user_ptr);
    if (err < 0) {
        return 0;
    }

    if (copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            request->arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            0,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline int emit_bpf_exit_bytes_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    struct bpf_exit_bytes_request *request)
{
    u32 max_len = request->max_len;
    if (max_len == 0 || max_len > BPF_DIRECT_OBJ_INFO_MAX ||
        request->storage_len < max_len ||
        request->storage_len != BPF_DIRECT_BYTES_BUCKET_512) {
        return 0;
    }

    // Keep the reservation constant so the verifier can prove every dynptr bucket access.
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_OBJ_INFO_MAX;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    u16 flags = 0;
    u32 payload_size = capture_bpf_exit_bytes_tlv_direct(
        &ptr,
        payload_offset,
        request,
        &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {.seq = sequence};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body,
        p,
        ret_value,
        duration,
        payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return 1;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
    return 1;
}

#include "syscall_bpf_prog_query_exit_direct_event_v2.h"

static __always_inline int emit_bpf_obj_info_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration,
    u64 info_ptr,
    u32 info_len)
{
    struct bpf_exit_bytes_request request = {
        .user_ptr = info_ptr,
        .user_len = info_len,
        .max_len = BPF_DIRECT_OBJ_INFO_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_OBJ_INFO_ARG,
    };
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

#include "syscall_bpf_next_id_exit_direct_event_v2.h"

static __always_inline int emit_bpf_prog_load_log_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_PROG_LOAD ||
        ret_value >= 0) {
        return 0;
    }

    u32 log_size = 0;
    u32 log_true_size = 0;
    u64 log_buf = 0;
    if (!bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_PROG_LOAD_LOG_SIZE_OFF,
            &log_size) ||
        !bpf_attr_read_u64_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_PROG_LOAD_LOG_BUF_OFF,
            &log_buf) ||
        !bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_PROG_LOAD_LOG_TRUE_SIZE_OFF,
            &log_true_size) ||
        !log_buf || log_size == 0 || log_true_size == 0) {
        return 0;
    }

    u32 requested_len = log_true_size;
    if (requested_len > log_size) {
        requested_len = log_size;
    }
    struct bpf_exit_bytes_request request = {
        .user_ptr = log_buf,
        .user_len = requested_len,
        .max_len = BPF_DIRECT_PROG_LOAD_LOG_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_LOG_BUF_ARG,
    };
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

static __always_inline int emit_bpf_btf_load_log_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_BTF_LOAD ||
        ret_value >= 0) {
        return 0;
    }

    u32 log_size = 0;
    u32 log_true_size = 0;
    u64 log_buf = 0;
    if (!bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_BTF_LOG_SIZE_OFF,
            &log_size) ||
        !bpf_attr_read_u64_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_BTF_LOG_BUF_OFF,
            &log_buf) ||
        !bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_BTF_LOG_TRUE_SIZE_OFF,
            &log_true_size) ||
        !log_buf || log_size == 0 || log_true_size == 0) {
        return 0;
    }

    u32 requested_len = log_true_size;
    if (requested_len > log_size) {
        requested_len = log_size;
    }
    struct bpf_exit_bytes_request request = {
        .user_ptr = log_buf,
        .user_len = requested_len,
        .max_len = BPF_DIRECT_BTF_LOG_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_BTF_LOG_BUF_ARG,
    };
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

#include "syscall_bpf_map_exit_direct_event_v2.h"

static __always_inline int emit_bpf_prog_stream_read_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        p->args[0] != BPF_DIRECT_PROG_STREAM_READ_BY_FD) {
        return 0;
    }

    u64 stream_buf = 0;
    u32 stream_buf_len = 0;
    if (!bpf_attr_read_u64_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_PROG_STREAM_BUF_OFF,
            &stream_buf) ||
        !bpf_attr_read_u32_direct(
            p->args[1],
            p->args[2],
            BPF_DIRECT_PROG_STREAM_BUF_LEN_OFF,
            &stream_buf_len) ||
        !stream_buf || stream_buf_len == 0) {
        return 0;
    }

    struct bpf_exit_bytes_request request = {
        .user_ptr = stream_buf,
        .user_len = stream_buf_len,
        .max_len = BPF_DIRECT_STREAM_BUF_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_STREAM_BUF_ARG,
    };
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

#include "syscall_bpf_test_run_exit_direct_event_v2.h"
#include "syscall_bpf_task_fd_query_exit_direct_event_v2.h"

static __always_inline int emit_bpf_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id)) {
        return 0;
    }

    if (p->args[0] == BPF_DIRECT_MAP_GET_NEXT_KEY) {
        return emit_bpf_map_get_next_key_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_PROG_QUERY) {
        return emit_bpf_prog_query_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_MAP_LOOKUP_ELEM ||
        p->args[0] == BPF_DIRECT_MAP_LOOKUP_AND_DELETE_ELEM) {
        return emit_bpf_map_lookup_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_MAP_LOOKUP_BATCH ||
        p->args[0] == BPF_DIRECT_MAP_LOOKUP_AND_DELETE_BATCH) {
        return emit_bpf_map_batch_lookup_exit_event_v2_direct(p, ret_value, duration);
    }

    if (is_bpf_get_next_id_command_direct(p->args[0])) {
        return emit_bpf_get_next_id_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_OBJ_GET_INFO_BY_FD) {
        if (ret_value != 0) {
            return 0;
        }
        u32 info_len = 0;
        u64 info_ptr = 0;
        if (!bpf_attr_read_u32_direct(
                p->args[1],
                p->args[2],
                BPF_DIRECT_OBJ_INFO_LEN_OFF,
                &info_len) ||
            !bpf_attr_read_u64_direct(
                p->args[1],
                p->args[2],
                BPF_DIRECT_OBJ_INFO_PTR_OFF,
                &info_ptr) ||
            !info_ptr || info_len == 0) {
            return 0;
        }
        return emit_bpf_obj_info_exit_event_v2_direct(
            p,
            ret_value,
            duration,
            info_ptr,
            info_len);
    }

    if (p->args[0] == BPF_DIRECT_BTF_LOAD) {
        return emit_bpf_btf_load_log_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_PROG_STREAM_READ_BY_FD) {
        return emit_bpf_prog_stream_read_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_PROG_TEST_RUN) {
        return emit_bpf_prog_test_run_exit_event_v2_direct(p, ret_value, duration);
    }

    if (p->args[0] == BPF_DIRECT_TASK_FD_QUERY) {
        return emit_bpf_task_fd_query_exit_event_v2_direct(p, ret_value, duration);
    }

    return emit_bpf_prog_load_log_exit_event_v2_direct(p, ret_value, duration);
}

#endif
