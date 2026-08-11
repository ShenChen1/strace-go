#ifndef STRACE_GO_SYSCALL_PAYLOAD_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_PAYLOAD_CAPTURE_DIRECT_EVENT_V2_H

static __always_inline u32 capture_openat_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_OPENAT_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, PAYLOAD_TLV_OPENAT_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > PAYLOAD_TLV_OPENAT_MAX) {
                copied_len = PAYLOAD_TLV_OPENAT_MAX;
            } else {
                copied_len = (u32)n;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            arg_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_write_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 args[6],
    u16 *event_flags)
{
    u64 user_ptr = args[1];
    u32 user_len = payload_tlv_clamp_u32(args[2]);
    u32 copied_len = payload_tlv_copy_len(args[2], PAYLOAD_TLV_WRITE_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (copied_len > 0) {
        if (!user_ptr) {
            probe_ret = -1;
            copied_len = 0;
        } else {
            void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_WRITE_MAX);
            if (!payload_data) {
                record_ringbuf_copy_fail();
                probe_ret = -1;
                copied_len = 0;
            } else {
                long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
                if (err < 0) {
                    probe_ret = err;
                    copied_len = 0;
                }
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            1,
            0,
            user_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_exec_path_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 path_index,
    u64 user_ptr)
{
    u32 copied_len = 0;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, EXEC_PATH_SNAPSHOT_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
        } else {
            long n = bpf_probe_read_user_str(payload_data, EXEC_PATH_SNAPSHOT_MAX, (void *)user_ptr);
            if (n < 0) {
                probe_ret = n;
            } else if (n > EXEC_PATH_SNAPSHOT_MAX) {
                copied_len = EXEC_PATH_SNAPSHOT_MAX;
            } else {
                copied_len = (u32)n;
            }
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRING,
            path_index,
            0,
            copied_len,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void capture_exec_argv_records_direct(
    struct bpf_dynptr *ptr,
    u32 records_offset,
    u64 array,
    u16 *count,
    s32 *status,
    u64 *next)
{
    *count = 0;
    *status = -1;
    *next = array;

    if (!array) {
        *status = 0;
        return;
    }

    for (u32 i = 0; i < EXEC_ARG_MAX; i++) {
        struct exec_arg_snapshot arg = {};
        u64 slot = array + i * sizeof(u64);
        u64 user_ptr = 0;
        if (bpf_probe_read_user(&user_ptr, sizeof(user_ptr), (void *)slot) < 0) {
            *status = -1;
            *next = slot;
            break;
        }
        if (!user_ptr) {
            *status = 0;
            break;
        }

        arg.ptr = user_ptr;
        arg.len = bpf_probe_read_user_str(arg.data, sizeof(arg.data), (void *)user_ptr);
        long ret = bpf_dynptr_write(ptr, records_offset + i * sizeof(arg), &arg, sizeof(arg), 0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            *status = -1;
            break;
        }
        *count = i + 1;

        if (i == EXEC_ARG_MAX - 1) {
            u64 next_slot = array + EXEC_ARG_MAX * sizeof(u64);
            u64 next_ptr = 0;
            if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                *status = -1;
                *next = next_slot;
            } else if (!next_ptr) {
                *status = 0;
            } else {
                *status = 1;
            }
        }
    }
}

static __always_inline void capture_exec_env_records_direct(
    struct bpf_dynptr *ptr,
    u32 records_offset,
    u64 array,
    u16 *count,
    s32 *status,
    u64 *next)
{
    *count = 0;
    *status = -1;
    *next = array;

    if (!array) {
        *status = 0;
        return;
    }

    for (u32 i = 0; i < EXEC_ENV_MAX; i++) {
        struct exec_arg_snapshot arg = {};
        u64 slot = array + i * sizeof(u64);
        u64 user_ptr = 0;
        if (bpf_probe_read_user(&user_ptr, sizeof(user_ptr), (void *)slot) < 0) {
            *status = -1;
            *next = slot;
            break;
        }
        if (!user_ptr) {
            *status = 0;
            break;
        }

        arg.ptr = user_ptr;
        arg.len = bpf_probe_read_user_str(arg.data, sizeof(arg.data), (void *)user_ptr);
        long ret = bpf_dynptr_write(ptr, records_offset + i * sizeof(arg), &arg, sizeof(arg), 0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            *status = -1;
            break;
        }
        *count = i + 1;

        if (i == EXEC_ENV_MAX - 1) {
            u64 next_slot = array + EXEC_ENV_MAX * sizeof(u64);
            u64 next_ptr = 0;
            if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                *status = -1;
                *next = next_slot;
            } else if (!next_ptr) {
                *status = 0;
            } else {
                *status = 1;
            }
        }
    }
}

static __always_inline int capture_exec_snapshot_direct(
    struct bpf_dynptr *ptr,
    u32 snapshot_offset,
    u64 argv_ptr,
    u64 env_ptr)
{
    struct exec_snapshot_header header = {};
    header.magic = EXEC_SNAPSHOT_MAGIC;

    u32 argv_records_offset = snapshot_offset + sizeof(header);
    u32 env_records_offset = snapshot_offset + sizeof(header) + EXEC_ARG_MAX * sizeof(struct exec_arg_snapshot);
    capture_exec_argv_records_direct(
        ptr,
        argv_records_offset,
        argv_ptr,
        &header.argv_count,
        &header.argv_status,
        &header.argv_next);
    capture_exec_env_records_direct(
        ptr,
        env_records_offset,
        env_ptr,
        &header.env_count,
        &header.env_status,
        &header.env_next);

    long ret = bpf_dynptr_write(ptr, snapshot_offset, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return sizeof(header) + EXEC_ARG_MAX * sizeof(struct exec_arg_snapshot) +
        header.env_count * sizeof(struct exec_arg_snapshot);
}

static __always_inline u32 capture_exec_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 path_index,
    u32 argv_index,
    u64 path_ptr,
    u64 argv_ptr,
    u64 env_ptr)
{
    u32 path_size = capture_exec_path_tlv_direct(ptr, payload_offset, path_index, path_ptr);
    u32 exec_offset = payload_offset + path_size;
    u32 snapshot_offset = exec_offset + PAYLOAD_TLV_HEADER_SIZE;
    u32 copied_len = 0;
    s32 probe_ret = -1;

    copied_len = capture_exec_snapshot_direct(ptr, snapshot_offset, argv_ptr, env_ptr);
    if (copied_len > 0) {
        probe_ret = 0;
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            exec_offset,
            PAYLOAD_TLV_KIND_EXEC_ARGS,
            argv_index,
            0,
            sizeof(struct exec_snapshot),
            copied_len,
            probe_ret,
            argv_ptr)) {
        return 0;
    }

    return path_size + PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_payload_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u32 sys_id,
    u64 args[6],
    u16 *event_flags)
{
    if (sys_id == SYS_OPEN || sys_id == SYS_CREAT) {
        return capture_openat_path_tlv_direct(ptr, payload_offset, 0, args[0]);
    }
    if (sys_id == SYS_OPENAT) {
        return capture_openat_path_tlv_direct(ptr, payload_offset, 1, args[1]);
    }
    if (sys_id == SYS_EXECVE) {
        return capture_exec_tlv_direct(
            ptr,
            payload_offset,
            0,
            1,
            args[0],
            args[1],
            args[2]);
    }
    if (sys_id == SYS_EXECVEAT) {
        return capture_exec_tlv_direct(
            ptr,
            payload_offset,
            1,
            2,
            args[1],
            args[2],
            args[3]);
    }
    if (is_write_payload_direct_syscall(sys_id)) {
        return capture_write_bytes_tlv_direct(ptr, payload_offset, args, event_flags);
    }
    return 0;
}

static __always_inline u32 capture_read_bytes_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    if (ret_value <= 0) {
        return 0;
    }

    u64 user_ptr = p->args[1];
    u32 user_len = payload_tlv_clamp_u32((u64)ret_value);
    u32 copied_len = payload_tlv_copy_len((u64)ret_value, PAYLOAD_TLV_READ_MAX);
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;

    if (!user_ptr) {
        probe_ret = -1;
        copied_len = 0;
    } else {
        void *payload_data = bpf_dynptr_data(ptr, data_offset, PAYLOAD_TLV_READ_MAX);
        if (!payload_data) {
            record_ringbuf_copy_fail();
            probe_ret = -1;
            copied_len = 0;
        } else {
            long err = bpf_probe_read_user(payload_data, copied_len, (void *)user_ptr);
            if (err < 0) {
                probe_ret = err;
                copied_len = 0;
            }
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
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

#endif
