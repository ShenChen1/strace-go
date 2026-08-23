#ifndef STRACE_GO_SYSCALL_BPF_PROG_LOAD_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_PROG_LOAD_DIRECT_EVENT_V2_H

#define BPF_DIRECT_PROG_LOAD_BASE_CAPACITY \
    (4 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_INSNS_MAX + BPF_DIRECT_LICENSE_MAX + BPF_DIRECT_LOG_BUF_MAX + BPF_DIRECT_SIGNATURE_MAX)
#define BPF_DIRECT_PROG_LOAD_DEBUG_CAPACITY \
    (4 * PAYLOAD_TLV_HEADER_SIZE + BPF_DIRECT_PROG_LOAD_FD_ARRAY_MAX + BPF_DIRECT_PROG_LOAD_FUNC_INFO_MAX + BPF_DIRECT_PROG_LOAD_LINE_INFO_MAX + BPF_DIRECT_PROG_LOAD_CORE_RELOS_MAX)
#define BPF_DIRECT_PROG_LOAD_CAPACITY \
    (BPF_DIRECT_PROG_LOAD_BASE_CAPACITY + BPF_DIRECT_PROG_LOAD_DEBUG_CAPACITY)

static __always_inline int is_bpf_prog_load_enter_direct(
    struct trace_event_raw_sys_enter *ctx)
{
    return ctx->args[0] == BPF_DIRECT_PROG_LOAD;
}

static __noinline u32 capture_bpf_prog_load_insns_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 insns,
    u32 insn_cnt,
    u16 *event_flags)
{
    if (!insns || insn_cnt == 0 || insn_cnt > 0x1fffffffU) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = insns,
        .user_len = insn_cnt * 8,
        .max_len = BPF_DIRECT_INSNS_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_INSNS_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __noinline u32 capture_bpf_prog_load_fd_array_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 fd_array = 0;
    u32 fd_array_cnt = 0;
    if (!bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_FD_ARRAY_OFF,
            &fd_array) ||
        !bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_FD_ARRAY_CNT_OFF,
            &fd_array_cnt) ||
        !fd_array ||
        fd_array_cnt == 0 ||
        fd_array_cnt > 0xffffffffU / sizeof(u32)) {
        return 0;
    }

    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = fd_array,
        .user_len = fd_array_cnt * sizeof(u32),
        .max_len = BPF_DIRECT_PROG_LOAD_FD_ARRAY_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_FD_ARRAY_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __noinline u32 capture_bpf_prog_load_func_info_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 func_info = 0;
    u32 rec_size = 0;
    u32 count = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_FUNC_INFO_REC_SIZE_OFF,
            &rec_size) ||
        !bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_FUNC_INFO_OFF,
            &func_info) ||
        !bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_FUNC_INFO_CNT_OFF,
            &count) ||
        !func_info ||
        rec_size == 0 ||
        count == 0) {
        return 0;
    }

    u64 user_len = (u64)rec_size * count;
    if (user_len > 0xffffffffU) {
        return 0;
    }

    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = func_info,
        .user_len = (u32)user_len,
        .max_len = BPF_DIRECT_PROG_LOAD_FUNC_INFO_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_FUNC_INFO_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __noinline u32 capture_bpf_prog_load_line_info_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 line_info = 0;
    u32 rec_size = 0;
    u32 count = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_LINE_INFO_REC_SIZE_OFF,
            &rec_size) ||
        !bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_LINE_INFO_OFF,
            &line_info) ||
        !bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_LINE_INFO_CNT_OFF,
            &count) ||
        !line_info ||
        rec_size < 16 ||
        count == 0) {
        return 0;
    }

    u64 user_len = (u64)rec_size * count;
    if (user_len > 0xffffffffU) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = line_info,
        .user_len = (u32)user_len,
        .max_len = BPF_DIRECT_PROG_LOAD_LINE_INFO_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_LINE_INFO_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __noinline u32 capture_bpf_prog_load_core_relos_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u64 core_relos = 0;
    u32 rec_size = 0;
    u32 count = 0;
    if (!bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_CORE_RELO_REC_SIZE_OFF,
            &rec_size) ||
        !bpf_attr_read_u64_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_CORE_RELOS_OFF,
            &core_relos) ||
        !bpf_attr_read_u32_direct(
            attr_ptr,
            attr_size,
            BPF_DIRECT_PROG_LOAD_CORE_RELO_CNT_OFF,
            &count) ||
        !core_relos ||
        rec_size < 16 ||
        count == 0) {
        return 0;
    }

    u64 user_len = (u64)rec_size * count;
    if (user_len > 0xffffffffU) {
        return 0;
    }
    struct bpf_nested_bytes_capture_request request = {
        .user_ptr = core_relos,
        .user_len = (u32)user_len,
        .max_len = BPF_DIRECT_PROG_LOAD_CORE_RELOS_MAX,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_PROG_LOAD_CORE_RELOS_ARG,
        .event_flags = event_flags,
    };
    return capture_bpf_bytes_tlv_direct(ptr, payload_offset, &request);
}

static __noinline u32 capture_bpf_prog_load_nested_tlv_direct(
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
            .storage_len = BPF_DIRECT_BYTES_BUCKET_256,
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
            .storage_len = BPF_DIRECT_BYTES_BUCKET_256,
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

static __noinline u32 capture_bpf_prog_load_debug_nested_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 attr_ptr,
    u64 attr_size,
    u16 *event_flags)
{
    u32 payload_size = 0;
    payload_size += capture_bpf_prog_load_fd_array_tlv_direct(
        ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        event_flags);
    payload_size += capture_bpf_prog_load_func_info_tlv_direct(
        ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        event_flags);
    payload_size += capture_bpf_prog_load_line_info_tlv_direct(
        ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        event_flags);
    payload_size += capture_bpf_prog_load_core_relos_tlv_direct(
        ptr,
        payload_offset + payload_size,
        attr_ptr,
        attr_size,
        event_flags);
    return payload_size;
}

#endif
