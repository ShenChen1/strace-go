#ifndef STRACE_GO_SYSCALL_FD_PATH_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_FD_PATH_DIRECT_EVENT_V2_H

#define FD_PATH_DIRECT_MAX 512
#define FD_PATH_DIRECT_MAX_ARGS 2
#define FD_PATH_AT_FDCWD (-100)
#define FD_PATH_STATE_PREFIX_SIZE 48
#define FD_PATH_DENTRY_MAX 8
#define FD_PATH_PROBE_PATH_FAILED (-36)
#define FD_PATH_DIRECT_SECTION_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + FD_PATH_STATE_PREFIX_SIZE + FD_PATH_DIRECT_MAX)

#include "syscall_fd_path_walk_direct_event_v2.h"

static __always_inline u32 fd_path_arg_mask(u32 sys_id)
{
    switch (sys_id) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_PREAD64:
    case SYS_PWRITE64:
    case SYS_READV:
    case SYS_WRITEV:
    case SYS_PREADV:
    case SYS_PWRITEV:
    case SYS_PREADV2:
    case SYS_PWRITEV2:
    case SYS_CLOSE:
    case SYS_FSTAT:
    case SYS_FCHDIR:
    case SYS_FSTATFS:
    case SYS_FCNTL:
    case SYS_EPOLL_WAIT:
    case SYS_EPOLL_PWAIT:
    case SYS_EPOLL_PWAIT2:
    case SYS_CACHESTAT:
    case SYS_OPEN_TREE:
    case SYS_FSPICK:
        return 1U << 0;
    case SYS_DUP2:
    case SYS_DUP3:
        return (1U << 0) | (1U << 1);
    case SYS_EPOLL_CTL:
        return (1U << 0) | (1U << 2);
    case SYS_OPENAT:
    case SYS_OPENAT2:
    case SYS_FCHOWNAT:
    case SYS_FUTIMESAT:
    case SYS_NEWFSTATAT:
    case SYS_UNLINKAT:
    case SYS_RENAMEAT:
    case SYS_LINKAT:
    case SYS_SYMLINKAT:
    case SYS_READLINKAT:
    case SYS_FCHMODAT:
    case SYS_FACCESSAT:
    case SYS_MKDIRAT:
    case SYS_FACCESSAT2:
        return 1U << 0;
    case SYS_DUP:
        return 1U << 0;
    default:
        return 0;
    }
}

static __always_inline u32 fd_path_arg_count(u32 sys_id)
{
    u32 mask = fd_path_arg_mask(sys_id);
    u32 count = 0;
    for (u32 i = 0; i < 6; i++) {
        if (mask & (1U << i)) {
            count++;
        }
    }
    if (count > FD_PATH_DIRECT_MAX_ARGS) {
        return FD_PATH_DIRECT_MAX_ARGS;
    }
    return count;
}

static __always_inline u32 fd_path_payload_capacity(u32 sys_id)
{
    return fd_path_arg_count(sys_id) * FD_PATH_DIRECT_SECTION_MAX;
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

static __always_inline void emit_fd_path_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u64 ts_ns)
{
    struct fd_path_scratch *scratch = lookup_fd_path_scratch();
    if (!scratch) {
        return;
    }
    copy_syscall_enter_args(scratch->args, ctx);
    u32 payload_capacity = fd_path_payload_capacity(sys_id);
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_ENTER_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = EVENT_FLAG_GENERIC_ENTER;
    u32 payload_size = capture_fd_paths_tlv_direct(&ptr, payload_offset, sys_id, scratch->args);
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

    struct syscall_enter_event_v2 body = {};
    init_syscall_enter_event_v2_from_args(&body, scratch->args, payload_size, 0, -1, -1);
    ret = bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_fd_path_or_no_payload_enter_event_v2_direct(
    u32 pid,
    u32 tid,
    u32 sys_id,
    struct trace_event_raw_sys_enter *ctx,
    u32 *cfg,
    u64 ts_ns)
{
    if (!cfg || !(*cfg & CONFIG_EMIT_ENTER)) {
        return;
    }
    if ((*cfg & CONFIG_FD_STATE) && fd_path_arg_count(sys_id) > 0) {
        emit_fd_path_enter_event_v2_direct(pid, tid, sys_id, ctx, ts_ns);
        return;
    }
    emit_syscall_enter_event_v2_direct(pid, tid, sys_id, ctx, EVENT_FLAG_GENERIC_ENTER, ts_ns);
}

#endif
