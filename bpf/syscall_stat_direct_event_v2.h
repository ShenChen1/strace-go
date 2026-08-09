#ifndef STRACE_GO_SYSCALL_STAT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_STAT_DIRECT_EVENT_V2_H

#define STAT_DIRECT_STRUCT_SIZE 144
#define STATFS_DIRECT_STRUCT_SIZE 120
#define STATX_DIRECT_STRUCT_SIZE 256
#define STAT_DIRECT_STRUCT_MAX_SIZE STATX_DIRECT_STRUCT_SIZE

static __always_inline int is_stat_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_STAT || sys_id == SYS_LSTAT || sys_id == SYS_FSTAT ||
        sys_id == SYS_NEWFSTATAT || sys_id == SYS_STATX ||
        sys_id == SYS_STATFS || sys_id == SYS_FSTATFS;
}

static __always_inline u32 stat_direct_struct_size(u32 sys_id)
{
    if (sys_id == SYS_STATFS || sys_id == SYS_FSTATFS) {
        return STATFS_DIRECT_STRUCT_SIZE;
    }
    if (sys_id == SYS_STATX) {
        return STATX_DIRECT_STRUCT_SIZE;
    }
    return STAT_DIRECT_STRUCT_SIZE;
}

static __always_inline u16 stat_direct_struct_arg_index(u32 sys_id)
{
    if (sys_id == SYS_STATX) {
        return 4;
    }
    if (sys_id == SYS_NEWFSTATAT) {
        return 2;
    }
    return 1;
}

static __always_inline u64 stat_direct_struct_user_ptr(struct pending_syscall *p)
{
    if (p->sys_id == SYS_STATX) {
        return p->args[4];
    }
    if (p->sys_id == SYS_NEWFSTATAT) {
        return p->args[2];
    }
    return p->args[1];
}

static __always_inline u32 capture_stat_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p)
{
    u16 arg_index = stat_direct_struct_arg_index(p->sys_id);
    u64 user_ptr = stat_direct_struct_user_ptr(p);
    if (!user_ptr) {
        return 0;
    }

    u32 struct_size = stat_direct_struct_size(p->sys_id);
    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = bpf_dynptr_data(ptr, data_offset, STAT_DIRECT_STRUCT_MAX_SIZE);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else if (p->sys_id == SYS_STATX) {
        long err = bpf_probe_read_user(payload_data, STATX_DIRECT_STRUCT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    } else if (p->sys_id == SYS_STATFS || p->sys_id == SYS_FSTATFS) {
        long err = bpf_probe_read_user(payload_data, STATFS_DIRECT_STRUCT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    } else {
        long err = bpf_probe_read_user(payload_data, STAT_DIRECT_STRUCT_SIZE, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_stat_struct_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + STAT_DIRECT_STRUCT_MAX_SIZE;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = 0;
    if (ret_value >= 0) {
        payload_size = capture_stat_struct_tlv_direct(&ptr, payload_offset, p);
    }
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(&header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id, out_size, ts_ns);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
