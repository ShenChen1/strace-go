#ifndef STRACE_GO_SYSCALL_EPOLL_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_EPOLL_CAPTURE_DIRECT_EVENT_V2_H

struct epoll_fd_path_scan_context {
    struct fd_path_scratch *scratch;
    u64 user_ptr;
    u32 count;
};

static long epoll_fd_path_scan_callback(u32 index, void *data)
{
    struct epoll_fd_path_scan_context *scan = data;
    if (index >= scan->count) {
        return 1;
    }

    s32 fd = -1;
    u64 offset = (u64)index * EPOLL_DIRECT_EVENT_SIZE +
        EPOLL_DIRECT_EVENT_DATA_OFFSET;
    if (bpf_probe_read_user(
            &fd,
            sizeof(fd),
            (void *)(scan->user_ptr + offset)) < 0 ||
        fd < 0 || (u32)fd >= FD_STATE_MAX_FD) {
        return 0;
    }
    fd_path_nested_add_window_candidate(scan->scratch, fd);
    return 0;
}

static __always_inline u32 collect_epoll_fd_path_candidates_direct(
    struct pending_syscall *p,
    s64 ret_value)
{
    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg || !(*cfg & CONFIG_FD_STATE) || !p ||
        !is_epoll_wait_direct_syscall(p->sys_id) || ret_value <= 0 ||
        !p->args[1]) {
        return 0;
    }

    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return 0;
    }

    u64 count = (u64)ret_value;
    if (count > EPOLL_DIRECT_EVENT_SLOT_MAX) {
        count = EPOLL_DIRECT_EVENT_SLOT_MAX;
    }
    scratch->nested_fd_count = 0;
    struct epoll_fd_path_scan_context scan = {
        .scratch = scratch,
        .user_ptr = p->args[1],
        .count = (u32)count,
    };
    bpf_loop(EPOLL_DIRECT_EVENT_SLOT_MAX, epoll_fd_path_scan_callback, &scan, 0);
    return scratch->nested_fd_count;
}

static __always_inline u32 capture_epoll_events_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u64 user_ptr = p->args[1];
    u32 user_len = epoll_events_user_len(ret_value);
    u32 target_len = epoll_events_copy_len(ret_value);
    if (user_len == 0 || !user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    for (u16 i = 0; i < EPOLL_DIRECT_EVENT_SLOT_MAX; i++) {
        u32 slot_offset = (u32)i * EPOLL_DIRECT_EVENT_SIZE;
        if (slot_offset >= target_len) {
            break;
        }

        u8 event_data[EPOLL_DIRECT_EVENT_SIZE] = {};
        long err = bpf_probe_read_user(&event_data, EPOLL_DIRECT_EVENT_SIZE, (void *)(user_ptr + slot_offset));
        if (err < 0) {
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }

        err = bpf_dynptr_write(ptr, data_offset + copied_len, &event_data, EPOLL_DIRECT_EVENT_SIZE, 0);
        if (err < 0) {
            record_ringbuf_copy_fail();
            if (copied_len == 0) {
                probe_ret = err;
            }
            break;
        }
        copied_len += EPOLL_DIRECT_EVENT_SIZE;
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_epoll_timeout_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6])
{
    u64 user_ptr = args[3];
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = EPOLL_DIRECT_TIMEOUT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, EPOLL_DIRECT_TIMEOUT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, EPOLL_DIRECT_TIMEOUT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            0,
            EPOLL_DIRECT_TIMEOUT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_epoll_ctl_event_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6])
{
    u64 user_ptr = args[3];
    if (!user_ptr) {
        return 0;
    }

    s32 probe_ret = 0;
    u32 copied_len = EPOLL_DIRECT_EVENT_SIZE;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, EPOLL_DIRECT_EVENT_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, EPOLL_DIRECT_EVENT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            3,
            0,
            EPOLL_DIRECT_EVENT_SIZE,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
