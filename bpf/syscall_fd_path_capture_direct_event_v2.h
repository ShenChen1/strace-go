#ifndef STRACE_GO_SYSCALL_FD_PATH_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_PATH_CAPTURE_DIRECT_EVENT_V2_H

#include "syscall_fd_path_walk_direct_event_v2.h"

static __always_inline int fd_path_nested_candidate_exists(
    const struct fd_path_scratch *scratch,
    s32 fd)
{
    u32 count = scratch->nested_fd_count;
    return (count > 0 && scratch->nested_fd0 == fd) ||
        (count > 1 && scratch->nested_fd1 == fd) ||
        (count > 2 && scratch->nested_fd2 == fd) ||
        (count > 3 && scratch->nested_fd3 == fd);
}

static __always_inline void fd_path_nested_add_candidate(
    struct fd_path_scratch *scratch,
    s32 fd)
{
    u32 count = scratch->nested_fd_count;
    if (count >= FD_PATH_NESTED_MAX || fd_path_nested_candidate_exists(scratch, fd)) {
        return;
    }
    if (count == 0) {
        scratch->nested_fd0 = fd;
    } else if (count == 1) {
        scratch->nested_fd1 = fd;
    } else if (count == 2) {
        scratch->nested_fd2 = fd;
    } else {
        scratch->nested_fd3 = fd;
    }
    scratch->nested_fd_count = count + 1;
}

static __always_inline void fd_path_nested_add_poll_candidate(
    struct fd_path_scratch *scratch,
    s32 fd)
{
    u32 count = scratch->nested_fd_count;
    if (count < FD_PATH_NESTED_MAX - 1) {
        fd_path_nested_add_candidate(scratch, fd);
        return;
    }
    if (fd_path_nested_candidate_exists(scratch, fd)) {
        return;
    }
    scratch->nested_fd3 = fd;
    scratch->nested_fd_count = FD_PATH_NESTED_MAX;
}

static __always_inline u32 capture_fd_cwd_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset)
{
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = task ? BPF_CORE_READ(task, fs) : 0;
    struct path cwd = {};
    long read_ret = fs ? BPF_CORE_READ_INTO(&cwd, fs, pwd) : -1;
    if (read_ret < 0) {
        payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            PAYLOAD_TLV_FD_PATH_CWD_ARG_INDEX,
            0,
            0,
            0,
            (s32)read_ret,
            0);
        return PAYLOAD_TLV_HEADER_SIZE;
    }

    long path_ret = read_dentry_path_direct(ptr, data_offset, &cwd);
    if (path_ret <= 0 || path_ret >= FD_PATH_DIRECT_MAX) {
        payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            PAYLOAD_TLV_FD_PATH_CWD_ARG_INDEX,
            0,
            0,
            0,
            (s32)path_ret,
            0);
        return PAYLOAD_TLV_HEADER_SIZE;
    }

    u32 path_len = (u32)path_ret;
    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            PAYLOAD_TLV_FD_PATH_CWD_ARG_INDEX,
            0,
            path_len,
            path_len,
            0,
            0)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + path_len;
}

static __always_inline u32 capture_fd_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    s32 fd)
{
    if (fd == FD_PATH_AT_FDCWD) {
        return capture_fd_cwd_path_tlv_direct(ptr, payload_offset);
    }
    struct file *file = lookup_current_fd_file(fd);
    u32 state_len = 0;
    if (!file) {
        payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            arg_index,
            0,
            0,
            0,
            FD_STATE_PROBE_READ_FAILED,
            0);
        return PAYLOAD_TLV_HEADER_SIZE;
    }

    struct fd_state_snapshot state = {};
    if (read_fd_state_snapshot_from_file(file, fd, &state) == 0) {
        if (bpf_dynptr_write(
                ptr,
                payload_offset + PAYLOAD_TLV_HEADER_SIZE,
                &state,
                sizeof(state),
                0) == 0) {
            state_len = FD_PATH_STATE_PREFIX_SIZE;
        } else {
            record_ringbuf_copy_fail();
        }
    }

    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE + state_len;
    struct path file_path = {};
    if (BPF_CORE_READ_INTO(&file_path, file, f_path) < 0) {
        payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            arg_index,
            0,
            0,
            0,
            FD_PATH_PROBE_PATH_FAILED,
            0);
        return PAYLOAD_TLV_HEADER_SIZE;
    }
    long path_ret = read_dentry_path_direct(ptr, data_offset, &file_path);
    if (path_ret <= 0 || path_ret >= FD_PATH_DIRECT_MAX) {
        payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            arg_index,
            0,
            0,
            0,
            (s32)path_ret,
            0);
        return PAYLOAD_TLV_HEADER_SIZE;
    }

    u32 path_len = (u32)path_ret;
    u32 copied_len = state_len + path_len;
    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_FD_PATH,
            arg_index,
            0,
            path_len,
            copied_len,
            0,
            0)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_fd_paths_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    u64 args[6])
{
    u32 mask = fd_path_arg_mask(sys_id);
    u32 payload_size = 0;
    for (u16 arg_index = 0; arg_index < 6; arg_index++) {
        if (!(mask & (1U << arg_index))) {
            continue;
        }
        payload_size += capture_fd_path_tlv_direct(
            ptr,
            payload_offset + payload_size,
            arg_index,
            (s32)args[arg_index]);
        if (payload_size >= FD_PATH_DIRECT_MAX_ARGS * FD_PATH_DIRECT_SECTION_MAX) {
            break;
        }
    }
    return payload_size;
}

#endif
