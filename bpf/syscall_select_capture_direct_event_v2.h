#ifndef STRACE_GO_SYSCALL_SELECT_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_SELECT_CAPTURE_DIRECT_EVENT_V2_H

struct select_fdset_capture_request {
    u64 user_ptr;
    u64 nfds;
    u16 arg_index;
    u16 tlv_flags;
};

struct pselect6_sigmask_wrapper {
    u64 sigmask_ptr;
    u64 sigsetsize;
};

struct pselect6_sigmask_capture_request {
    u64 user_ptr;
    u64 raw_user_len;
    u16 arg_index;
    u16 tlv_flags;
};

static __always_inline long select_direct_read_fdset_small(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len == 1) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 1);
        return payload_data ? bpf_probe_read_user(payload_data, 1, (void *)user_ptr) : -1;
    }
    if (user_len == 2) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 2);
        return payload_data ? bpf_probe_read_user(payload_data, 2, (void *)user_ptr) : -1;
    }
    if (user_len == 3) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 3);
        return payload_data ? bpf_probe_read_user(payload_data, 3, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, 4);
    return payload_data ? bpf_probe_read_user(payload_data, 4, (void *)user_ptr) : -1;
}

static __always_inline long select_direct_read_fdset_medium(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len == 5) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 5);
        return payload_data ? bpf_probe_read_user(payload_data, 5, (void *)user_ptr) : -1;
    }
    if (user_len == 6) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 6);
        return payload_data ? bpf_probe_read_user(payload_data, 6, (void *)user_ptr) : -1;
    }
    if (user_len == 7) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 7);
        return payload_data ? bpf_probe_read_user(payload_data, 7, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, 8);
    return payload_data ? bpf_probe_read_user(payload_data, 8, (void *)user_ptr) : -1;
}

static __always_inline long select_direct_read_fdset_wide(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u64 user_ptr,
    u32 user_len)
{
    void *payload_data = 0;
    if (user_len <= 16) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 16);
        return payload_data ? bpf_probe_read_user(payload_data, 16, (void *)user_ptr) : -1;
    }
    if (user_len <= 32) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 32);
        return payload_data ? bpf_probe_read_user(payload_data, 32, (void *)user_ptr) : -1;
    }
    if (user_len <= 64) {
        payload_data = bpf_dynptr_data(ptr, data_offset, 64);
        return payload_data ? bpf_probe_read_user(payload_data, 64, (void *)user_ptr) : -1;
    }
    payload_data = bpf_dynptr_data(ptr, data_offset, SELECT_DIRECT_FDSET_SIZE);
    return payload_data ? bpf_probe_read_user(payload_data, SELECT_DIRECT_FDSET_SIZE, (void *)user_ptr) : -1;
}

static __noinline u32 capture_select_fdset_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    const struct select_fdset_capture_request *request)
{
    u32 user_len = select_direct_fdset_user_len(request->nfds);
    if (user_len == 0 || !request->user_ptr) {
        return 0;
    }

    u32 copied_len = user_len;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    long err = 0;
    if (user_len <= 4) {
        err = select_direct_read_fdset_small(ptr, data_offset, request->user_ptr, user_len);
    } else if (user_len <= 8) {
        err = select_direct_read_fdset_medium(ptr, data_offset, request->user_ptr, user_len);
    } else {
        err = select_direct_read_fdset_wide(ptr, data_offset, request->user_ptr, user_len);
    }
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            request->arg_index,
            request->tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __noinline u32 capture_select_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = SELECT_DIRECT_TIMEVAL_SIZE;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, SELECT_DIRECT_TIMEVAL_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, SELECT_DIRECT_TIMEVAL_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            4,
            tlv_flags,
            SELECT_DIRECT_TIMEVAL_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __noinline u32 capture_pselect6_sigmask_wrapper_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u16 tlv_flags,
    struct pselect6_sigmask_wrapper *wrapper)
{
    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = SELECT_DIRECT_PSELECT6_WRAPPER_SIZE;
    s32 probe_ret = 0;
    long err = bpf_probe_read_user(
        wrapper,
        SELECT_DIRECT_PSELECT6_WRAPPER_SIZE,
        (void *)user_ptr);
    if (err < 0) {
        probe_ret = err;
        copied_len = 0;
    } else if (bpf_dynptr_write(
                   ptr,
                   payload_offset + PAYLOAD_TLV_HEADER_SIZE,
                   wrapper,
                   SELECT_DIRECT_PSELECT6_WRAPPER_SIZE,
                   0) < 0) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            5,
            tlv_flags,
            SELECT_DIRECT_PSELECT6_WRAPPER_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __noinline u32 capture_pselect6_sigmask_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    const struct pselect6_sigmask_capture_request *request)
{
    u32 user_len = payload_tlv_clamp_u32(request->raw_user_len);
    if (!request->user_ptr || user_len == 0) {
        return 0;
    }

    u32 copied_len = payload_tlv_copy_len(
        request->raw_user_len,
        SELECT_DIRECT_PSELECT6_SIGMASK_SIZE);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(
        ptr,
        data_offset,
        SELECT_DIRECT_PSELECT6_SIGMASK_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(
            payload_data,
            copied_len,
            (void *)request->user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            request->arg_index,
            request->tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline long read_select_fdset_candidates_direct(
    struct fd_path_scratch *scratch,
    u64 user_ptr,
    u32 user_len)
{
    if (user_len == FD_PATH_NESTED_SCAN_BYTES) {
        return bpf_probe_read_user(
            scratch->nested_fdset,
            FD_PATH_NESTED_SCAN_BYTES,
            (void *)user_ptr);
    }
    user_len &= FD_PATH_NESTED_SCAN_BYTES - 1;
    if (user_len == 0) {
        return -1;
    }
    return bpf_probe_read_user(scratch->nested_fdset, user_len, (void *)user_ptr);
}

struct select_fd_scan_context {
    struct fd_path_scratch *scratch;
    u32 bit_count;
};

static long select_fd_scan_callback(u32 fd, void *data)
{
    struct select_fd_scan_context *scan = data;
    struct fd_path_scratch *scratch = scan->scratch;
    if (fd >= scan->bit_count ||
        scratch->nested_fd_count >= SELECT_DIRECT_FD_PATH_MAX) {
        return 1;
    }
    u32 byte_index = (fd >> 3) & (FD_PATH_NESTED_SCAN_BYTES - 1);
    if (!(scratch->nested_fdset[byte_index] & (1U << (fd & 7)))) {
        return 0;
    }
    fd_path_nested_add_candidate(scratch, (s32)fd);
    return 0;
}

static __always_inline void collect_select_fdset_candidates_direct(
    struct fd_path_scratch *scratch,
    u64 user_ptr,
    u64 nfds)
{
    u32 user_len = select_direct_fdset_user_len(nfds);
    if (!user_ptr || user_len == 0 ||
        scratch->nested_fd_count >= SELECT_DIRECT_FD_PATH_MAX) {
        return;
    }
    if (read_select_fdset_candidates_direct(scratch, user_ptr, user_len) < 0) {
        return;
    }
    struct select_fd_scan_context scan = {
        .scratch = scratch,
        .bit_count = user_len * 8,
    };
    bpf_loop(FD_PATH_NESTED_SCAN_BYTES * 8, select_fd_scan_callback, &scan, 0);
}

static __always_inline u32 collect_select_fd_path_candidates_direct(
    u64 nfds,
    u64 readfds,
    u64 writefds,
    u64 exceptfds)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return 0;
    }
    scratch->nested_fd_count = 0;
    collect_select_fdset_candidates_direct(scratch, readfds, nfds);
    collect_select_fdset_candidates_direct(scratch, writefds, nfds);
    collect_select_fdset_candidates_direct(scratch, exceptfds, nfds);
    return scratch->nested_fd_count;
}

static __noinline u32 capture_select_payloads_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    const u64 *args,
    u16 tlv_flags,
    u8 capture_policy)
{
    u32 payload_size = 0;
    struct select_fdset_capture_request request = {};
    request.nfds = args[0];
    request.tlv_flags = tlv_flags;
    if (capture_policy & SELECT_DIRECT_CAPTURE_FDSETS) {
        request.user_ptr = args[1];
        request.arg_index = SELECT_DIRECT_FDSET_ARG_BASE;
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request);

        request.user_ptr = args[2];
        request.arg_index = 2;
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request);

        request.user_ptr = args[3];
        request.arg_index = SELECT_DIRECT_FDSET_ARG_LAST;
        payload_size += capture_select_fdset_tlv_direct(
            ptr,
            payload_offset + payload_size,
            &request);
    }
    if (capture_policy & SELECT_DIRECT_CAPTURE_TIMEOUT) {
        payload_size += capture_select_timeout_tlv_direct(
            ptr,
            payload_offset + payload_size,
            args[4],
            tlv_flags);
    }
    if (capture_policy & SELECT_DIRECT_CAPTURE_SIGMASK) {
        struct pselect6_sigmask_wrapper wrapper = {};
        payload_size += capture_pselect6_sigmask_wrapper_tlv_direct(
            ptr,
            payload_offset + payload_size,
            args[5],
            tlv_flags,
            &wrapper);
        if (wrapper.sigmask_ptr && wrapper.sigsetsize > 0) {
            struct pselect6_sigmask_capture_request request = {};
            request.user_ptr = wrapper.sigmask_ptr;
            request.raw_user_len = wrapper.sigsetsize;
            request.arg_index = SELECT_DIRECT_PSELECT6_SIGMASK_ARG_INDEX;
            request.tlv_flags = tlv_flags;
            payload_size += capture_pselect6_sigmask_tlv_direct(
                ptr,
                payload_offset + payload_size,
                &request);
        }
    }
    return payload_size;
}

#endif
