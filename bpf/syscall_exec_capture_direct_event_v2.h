#ifndef STRACE_GO_SYSCALL_EXEC_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_EXEC_CAPTURE_DIRECT_EVENT_V2_H

struct exec_records_capture_request {
    struct bpf_dynptr *ptr;
    u32 records_offset;
    u64 array;
    u16 *count;
    s32 *status;
    u64 *next;
};

struct exec_capture_request {
    struct bpf_dynptr *ptr;
    u32 payload_offset;
    u32 path_index;
    u32 argv_index;
    u64 path_ptr;
    u64 argv_ptr;
    u64 env_ptr;
};

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
    struct exec_records_capture_request *request)
{
    *request->count = 0;
    *request->status = -1;
    *request->next = request->array;

    if (!request->array) {
        *request->status = 0;
        return;
    }

    for (u32 i = 0; i < EXEC_ARG_MAX; i++) {
        struct exec_arg_snapshot arg = {};
        u64 slot = request->array + i * sizeof(u64);
        u64 user_ptr = 0;
        if (bpf_probe_read_user(&user_ptr, sizeof(user_ptr), (void *)slot) < 0) {
            *request->status = -1;
            *request->next = slot;
            break;
        }
        if (!user_ptr) {
            *request->status = 0;
            break;
        }

        arg.ptr = user_ptr;
        arg.len = bpf_probe_read_user_str(arg.data, sizeof(arg.data), (void *)user_ptr);
        long ret = bpf_dynptr_write(
            request->ptr,
            request->records_offset + i * sizeof(arg),
            &arg,
            sizeof(arg),
            0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            *request->status = -1;
            break;
        }
        *request->count = i + 1;

        if (i == EXEC_ARG_MAX - 1) {
            u64 next_slot = request->array + EXEC_ARG_MAX * sizeof(u64);
            u64 next_ptr = 0;
            if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                *request->status = -1;
                *request->next = next_slot;
            } else if (!next_ptr) {
                *request->status = 0;
            } else {
                *request->status = 1;
            }
        }
    }
}

static __always_inline void capture_exec_env_records_direct(
    struct exec_records_capture_request *request)
{
    *request->count = 0;
    *request->status = -1;
    *request->next = request->array;

    if (!request->array) {
        *request->status = 0;
        return;
    }

    for (u32 i = 0; i < EXEC_ENV_MAX; i++) {
        struct exec_arg_snapshot arg = {};
        u64 slot = request->array + i * sizeof(u64);
        u64 user_ptr = 0;
        if (bpf_probe_read_user(&user_ptr, sizeof(user_ptr), (void *)slot) < 0) {
            *request->status = -1;
            *request->next = slot;
            break;
        }
        if (!user_ptr) {
            *request->status = 0;
            break;
        }

        arg.ptr = user_ptr;
        arg.len = bpf_probe_read_user_str(arg.data, sizeof(arg.data), (void *)user_ptr);
        long ret = bpf_dynptr_write(
            request->ptr,
            request->records_offset + i * sizeof(arg),
            &arg,
            sizeof(arg),
            0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            *request->status = -1;
            break;
        }
        *request->count = i + 1;

        if (i == EXEC_ENV_MAX - 1) {
            u64 next_slot = request->array + EXEC_ENV_MAX * sizeof(u64);
            u64 next_ptr = 0;
            if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                *request->status = -1;
                *request->next = next_slot;
            } else if (!next_ptr) {
                *request->status = 0;
            } else {
                *request->status = 1;
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
    struct exec_records_capture_request argv_request = {};
    argv_request.ptr = ptr;
    argv_request.records_offset = argv_records_offset;
    argv_request.array = argv_ptr;
    argv_request.count = &header.argv_count;
    argv_request.status = &header.argv_status;
    argv_request.next = &header.argv_next;
    capture_exec_argv_records_direct(&argv_request);

    struct exec_records_capture_request env_request = {};
    env_request.ptr = ptr;
    env_request.records_offset = env_records_offset;
    env_request.array = env_ptr;
    env_request.count = &header.env_count;
    env_request.status = &header.env_status;
    env_request.next = &header.env_next;
    capture_exec_env_records_direct(&env_request);

    long ret = bpf_dynptr_write(ptr, snapshot_offset, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return sizeof(header) + EXEC_ARG_MAX * sizeof(struct exec_arg_snapshot) +
        header.env_count * sizeof(struct exec_arg_snapshot);
}

static __always_inline u32 capture_exec_tlv_direct(
    struct exec_capture_request *request)
{
    u32 path_size = capture_exec_path_tlv_direct(
        request->ptr,
        request->payload_offset,
        request->path_index,
        request->path_ptr);
    u32 exec_offset = request->payload_offset + path_size;
    u32 snapshot_offset = exec_offset + PAYLOAD_TLV_HEADER_SIZE;
    u32 copied_len = 0;
    s32 probe_ret = -1;

    copied_len = capture_exec_snapshot_direct(
        request->ptr,
        snapshot_offset,
        request->argv_ptr,
        request->env_ptr);
    if (copied_len > 0) {
        probe_ret = 0;
    }

    if (!payload_tlv_write_header_direct(
            request->ptr,
            exec_offset,
            PAYLOAD_TLV_KIND_EXEC_ARGS,
            request->argv_index,
            0,
            sizeof(struct exec_snapshot),
            copied_len,
            probe_ret,
            request->argv_ptr)) {
        return 0;
    }

    return path_size + PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
