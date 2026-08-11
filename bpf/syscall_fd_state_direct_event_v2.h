#ifndef STRACE_GO_SYSCALL_FD_STATE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_STATE_DIRECT_EVENT_V2_H

#define FD_STATE_MAX_FD (1U << 20)
#define FD_STATE_PROBE_INVALID_FD (-9)
#define FD_STATE_PROBE_READ_FAILED (-14)

static __always_inline int is_fd_state_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_OPEN || sys_id == SYS_OPENAT || sys_id == SYS_OPENAT2 ||
        sys_id == SYS_OPEN_TREE || sys_id == SYS_CREAT || sys_id == SYS_DUP ||
        sys_id == SYS_DUP2 || sys_id == SYS_DUP3 || sys_id == SYS_EVENTFD ||
        sys_id == SYS_EVENTFD2;
}

static __always_inline s32 read_fd_state_snapshot(
    s32 fd,
    struct fd_state_snapshot *snapshot)
{
    if (fd < 0 || (u32)fd >= FD_STATE_MAX_FD) {
        return FD_STATE_PROBE_INVALID_FD;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return FD_STATE_PROBE_READ_FAILED;
    }
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return FD_STATE_PROBE_READ_FAILED;
    }

    u32 max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((u32)fd >= max_fds) {
        return FD_STATE_PROBE_INVALID_FD;
    }
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) {
        return FD_STATE_PROBE_READ_FAILED;
    }

    struct file *file = 0;
    long read_ret = bpf_probe_read_kernel(&file, sizeof(file), fd_array + fd);
    if (read_ret < 0 || !file) {
        return FD_STATE_PROBE_READ_FAILED;
    }
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return FD_STATE_PROBE_READ_FAILED;
    }

    struct super_block *super = BPF_CORE_READ(inode, i_sb);
    *snapshot = (struct fd_state_snapshot){
        .fd = fd,
        .flags = FD_STATE_FLAG_IDENTITY | FD_STATE_FLAG_OFFSET,
        .mode = (u32)BPF_CORE_READ(inode, i_mode),
        .dev = super ? (u64)BPF_CORE_READ(super, s_dev) : 0,
        .rdev = (u64)BPF_CORE_READ(inode, i_rdev),
        .inode = (u64)BPF_CORE_READ(inode, i_ino),
        .offset = (s64)BPF_CORE_READ(file, f_pos),
    };
    return 0;
}

static __always_inline u32 capture_fd_state_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    s32 fd)
{
    struct fd_state_snapshot snapshot = {};
    s32 probe_ret = read_fd_state_snapshot(fd, &snapshot);
    u32 copied_len = probe_ret == 0 ? sizeof(snapshot) : 0;

    if (copied_len > 0) {
        long write_ret = bpf_dynptr_write(
            ptr,
            payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            &snapshot,
            sizeof(snapshot),
            0);
        if (write_ret < 0) {
            record_ringbuf_copy_fail();
            probe_ret = FD_STATE_PROBE_READ_FAILED;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_STATE,
            PAYLOAD_TLV_FD_STATE_ARG_INDEX,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT,
            sizeof(snapshot),
            copied_len,
            probe_ret,
            0)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_fd_state_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = PAYLOAD_TLV_HEADER_SIZE + FD_STATE_SNAPSHOT_SIZE;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    u64 ts_ns = p->enter_time + duration;
    struct bpf_dynptr ptr;
    long reserve_ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (reserve_ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = capture_fd_state_tlv_direct(&ptr, payload_offset, (s32)ret_value);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header,
        EVENT_TYPE_EXIT,
        flags,
        p->pid,
        p->tid,
        p->sys_id,
        out_size,
        ts_ns);
    reserve_ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (reserve_ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(&body, p, ret_value, duration, payload_size);
    reserve_ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (reserve_ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
