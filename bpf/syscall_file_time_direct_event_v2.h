#ifndef STRACE_GO_SYSCALL_FILE_TIME_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FILE_TIME_DIRECT_EVENT_V2_H

#define FILE_TIME_DIRECT_UTIMBUF_SIZE 16
#define FILE_TIME_DIRECT_TIMEVALS_SIZE 32
#define FILE_TIME_DIRECT_PAYLOAD_MAX (PAYLOAD_TLV_HEADER_SIZE + PATH_STAT_DIRECT_PATH_MAX + PAYLOAD_TLV_HEADER_SIZE + FILE_TIME_DIRECT_TIMEVALS_SIZE)

static __always_inline int is_file_time_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_UTIME || sys_id == SYS_UTIMES ||
        sys_id == SYS_FUTIMESAT || sys_id == SYS_UTIMENSAT;
}

static __always_inline u32 file_time_direct_value_size(u32 sys_id)
{
    if (sys_id == SYS_UTIME) {
        return FILE_TIME_DIRECT_UTIMBUF_SIZE;
    }
    return FILE_TIME_DIRECT_TIMEVALS_SIZE;
}

static __always_inline u32 capture_file_time_value_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u32 value_size)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = value_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    if (value_size == FILE_TIME_DIRECT_UTIMBUF_SIZE) {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, FILE_TIME_DIRECT_UTIMBUF_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, FILE_TIME_DIRECT_UTIMBUF_SIZE, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, FILE_TIME_DIRECT_TIMEVALS_SIZE);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, FILE_TIME_DIRECT_TIMEVALS_SIZE, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            0,
            value_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_file_time_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 path_arg,
    u64 path_ptr,
    u16 value_arg,
    u64 value_ptr,
    u32 value_size)
{
    u32 payload_size = capture_path_stat_path_tlv_direct(ptr, payload_offset, path_arg, path_ptr);
    payload_size += capture_file_time_value_tlv_direct(
        ptr,
        payload_offset + payload_size,
        value_arg,
        value_ptr,
        value_size);
    return payload_size;
}

static __always_inline void emit_file_time_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_ctx(&body, ctx, 0, 0, -1, -1);

    u16 path_arg = 0;
    u16 value_arg = 1;
    u64 path_ptr = body.args[0];
    u64 value_ptr = body.args[1];
    if (sys_id == SYS_FUTIMESAT || sys_id == SYS_UTIMENSAT) {
        path_arg = 1;
        value_arg = 2;
        path_ptr = body.args[1];
        value_ptr = body.args[2];
    }
    u32 value_size = file_time_direct_value_size(sys_id);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + FILE_TIME_DIRECT_PAYLOAD_MAX;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_file_time_payloads_tlv_direct(
        &ptr,
        payload_offset,
        path_arg,
        path_ptr,
        value_arg,
        value_ptr,
        value_size);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_ENTER, flags, pid, tid, sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    body.capture_len = payload_size;
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
