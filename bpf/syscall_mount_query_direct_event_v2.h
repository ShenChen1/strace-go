#ifndef STRACE_GO_SYSCALL_MOUNT_QUERY_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MOUNT_QUERY_DIRECT_EVENT_V2_H

#define MNT_ID_REQ_SIZE_FIELD_SIZE 4
#define MNT_ID_REQ_SIZE_VER0 24
#define MNT_ID_REQ_SIZE_VER1 32
#define MNT_ID_REQ_EXTENSION_MAX 256
#define STATMOUNT_FIXED_SIZE 512
#define STATMOUNT_STRING_MAX 4096
#define LISTMOUNT_ID_MAX 32
#define LISTMOUNT_ID_SIZE 8

#define MOUNT_QUERY_ENTER_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + MNT_ID_REQ_SIZE_FIELD_SIZE + \
     MNT_ID_REQ_SIZE_VER1 + MNT_ID_REQ_EXTENSION_MAX)
#define STATMOUNT_EXIT_PAYLOAD_CAPACITY \
    (3 * PAYLOAD_TLV_HEADER_SIZE + MNT_ID_REQ_SIZE_FIELD_SIZE + \
     STATMOUNT_FIXED_SIZE + STATMOUNT_STRING_MAX)
#define LISTMOUNT_EXIT_PAYLOAD_CAPACITY \
    (PAYLOAD_TLV_HEADER_SIZE + LISTMOUNT_ID_MAX * LISTMOUNT_ID_SIZE)

static __always_inline int is_mount_query_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_STATMOUNT || sys_id == SYS_LISTMOUNT;
}

static __always_inline u32 capture_mnt_id_req_size_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 *request_size,
    s32 *size_probe_ret)
{
    if (!user_ptr) {
        return 0;
    }

    u32 value = 0;
    s32 probe_ret = bpf_probe_read_user(&value, sizeof(value), (void *)user_ptr);
    u32 copied_len = probe_ret < 0 ? 0 : sizeof(value);
    if (probe_ret >= 0) {
        *request_size = value;
        probe_ret = 0;
    }
    *size_probe_ret = probe_ret;

    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_STRUCT, 0, 0,
            sizeof(value), copied_len, probe_ret, user_ptr)) {
        return 0;
    }
    if (copied_len > 0 && bpf_dynptr_write(
            ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            &value, sizeof(value), 0) < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mnt_id_req_base_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 request_size)
{
    if (request_size < MNT_ID_REQ_SIZE_VER0) {
        return 0;
    }

    u32 copied_len = request_size < MNT_ID_REQ_SIZE_VER1
        ? request_size : MNT_ID_REQ_SIZE_VER1;
    s32 probe_ret = 0;
    void *data = bpf_dynptr_data(
        ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MNT_ID_REQ_SIZE_VER1);
    if (!data) {
        record_ringbuf_copy_fail();
        copied_len = 0;
        probe_ret = -1;
    } else {
        long err = bpf_probe_read_user(data, copied_len, (void *)user_ptr);
        if (err < 0) {
            copied_len = 0;
            probe_ret = err;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_STRUCT, 0, 0,
            request_size < MNT_ID_REQ_SIZE_VER1 ? request_size : MNT_ID_REQ_SIZE_VER1,
            copied_len, probe_ret, user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mnt_id_req_extension_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u64 user_ptr,
    u32 request_size,
    u16 *event_flags)
{
    if (request_size <= MNT_ID_REQ_SIZE_VER1) {
        return 0;
    }

    u32 user_len = request_size - MNT_ID_REQ_SIZE_VER1;
    u32 copied_len = payload_tlv_copy_len(user_len, MNT_ID_REQ_EXTENSION_MAX);
    u64 extension_ptr = user_ptr + MNT_ID_REQ_SIZE_VER1;
    s32 probe_ret = 0;
    void *data = bpf_dynptr_data(
        ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MNT_ID_REQ_EXTENSION_MAX);
    if (extension_ptr < user_ptr || !data) {
        if (!data) {
            record_ringbuf_copy_fail();
        }
        copied_len = 0;
        probe_ret = -1;
    } else {
        long err = bpf_probe_read_user(data, copied_len, (void *)extension_ptr);
        if (err < 0) {
            copied_len = 0;
            probe_ret = err;
        }
    }

    if (probe_ret == 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_BYTES, 0, 0,
            user_len, copied_len, probe_ret, extension_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_mnt_id_req_enter_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct trace_event_raw_sys_enter *ctx,
    u16 *event_flags)
{
    u64 user_ptr = ctx->args[0];
    u32 request_size = 0;
    s32 size_probe_ret = -1;
    u32 payload_size = capture_mnt_id_req_size_tlv_direct(
        ptr, payload_offset, user_ptr, &request_size, &size_probe_ret);
    if (size_probe_ret < 0) {
        return payload_size;
    }
    payload_size += capture_mnt_id_req_base_tlv_direct(
        ptr, payload_offset + payload_size, user_ptr, request_size);
    payload_size += capture_mnt_id_req_extension_tlv_direct(
        ptr, payload_offset + payload_size, user_ptr, request_size, event_flags);
    return payload_size;
}

static __always_inline u32 capture_statmount_size_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u32 *result_size,
    s32 *size_probe_ret)
{
    u64 user_ptr = p->args[1];
    u64 buffer_size = p->args[2];
    if (!user_ptr || buffer_size < MNT_ID_REQ_SIZE_FIELD_SIZE) {
        return 0;
    }

    u32 value = 0;
    s32 probe_ret = bpf_probe_read_user(&value, sizeof(value), (void *)user_ptr);
    u32 copied_len = probe_ret < 0 ? 0 : sizeof(value);
    if (probe_ret >= 0) {
        *result_size = value;
        probe_ret = 0;
    }
    *size_probe_ret = probe_ret;
    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_STRUCT, 1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT, sizeof(value), copied_len,
            probe_ret, user_ptr)) {
        return 0;
    }
    if (copied_len > 0 && bpf_dynptr_write(
            ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            &value, sizeof(value), 0) < 0) {
        record_ringbuf_copy_fail();
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_statmount_fixed_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p)
{
    u64 user_ptr = p->args[1];
    u64 buffer_size = p->args[2];
    if (!user_ptr || buffer_size < MNT_ID_REQ_SIZE_FIELD_SIZE) {
        return 0;
    }
    u32 user_len = payload_tlv_copy_len(buffer_size, STATMOUNT_FIXED_SIZE);
    u32 copied_len = user_len;
    s32 probe_ret = 0;
    void *data = bpf_dynptr_data(
        ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        STATMOUNT_FIXED_SIZE);
    if (!data) {
        record_ringbuf_copy_fail();
        copied_len = 0;
        probe_ret = -1;
    } else {
        long err = bpf_probe_read_user(data, copied_len, (void *)user_ptr);
        if (err < 0) {
            copied_len = 0;
            probe_ret = err;
        }
    }
    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_STRUCT, 1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT, user_len, copied_len,
            probe_ret, user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_statmount_strings_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u32 result_size,
    u16 *event_flags)
{
    u64 user_ptr = p->args[1];
    u64 buffer_size = p->args[2];
    if (result_size <= STATMOUNT_FIXED_SIZE || result_size > buffer_size) {
        return 0;
    }
    u32 user_len = result_size - STATMOUNT_FIXED_SIZE;
    u32 copied_len = payload_tlv_copy_len(user_len, STATMOUNT_STRING_MAX);
    u64 string_ptr = user_ptr + STATMOUNT_FIXED_SIZE;
    s32 probe_ret = 0;
    void *data = bpf_dynptr_data(
        ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        STATMOUNT_STRING_MAX);
    if (string_ptr < user_ptr || !data) {
        if (!data) {
            record_ringbuf_copy_fail();
        }
        copied_len = 0;
        probe_ret = -1;
    } else {
        long err = bpf_probe_read_user(data, copied_len, (void *)string_ptr);
        if (err < 0) {
            copied_len = 0;
            probe_ret = err;
        }
    }
    if (probe_ret == 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_BYTES, 1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT, user_len, copied_len,
            probe_ret, string_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_statmount_exit_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 *event_flags)
{
    u32 result_size = 0;
    s32 size_probe_ret = -1;
    u32 payload_size = capture_statmount_size_tlv_direct(
        ptr, payload_offset, p, &result_size, &size_probe_ret);
    payload_size += capture_statmount_fixed_tlv_direct(
        ptr, payload_offset + payload_size, p);
    if (size_probe_ret >= 0) {
        payload_size += capture_statmount_strings_tlv_direct(
            ptr, payload_offset + payload_size, p, result_size, event_flags);
    }
    return payload_size;
}

static __always_inline u32 capture_listmount_ids_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    s64 ret_value,
    u16 *event_flags)
{
    u64 user_ptr = p->args[1];
    u64 count = p->args[2];
    if (!user_ptr || ret_value <= 0 || count == 0) {
        return 0;
    }
    u64 returned = (u64)ret_value < count ? (u64)ret_value : count;
    u32 user_len = returned > 0x1fffffffULL
        ? 0xffffffffU : (u32)(returned * LISTMOUNT_ID_SIZE);
    u64 copied_ids = returned < LISTMOUNT_ID_MAX
        ? returned : LISTMOUNT_ID_MAX;
    u32 copied_len = (u32)copied_ids * LISTMOUNT_ID_SIZE;
    s32 probe_ret = 0;
    void *data = bpf_dynptr_data(
        ptr, payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        LISTMOUNT_ID_MAX * LISTMOUNT_ID_SIZE);
    if (!data) {
        record_ringbuf_copy_fail();
        copied_len = 0;
        probe_ret = -1;
    } else {
        long err = bpf_probe_read_user(data, copied_len, (void *)user_ptr);
        if (err < 0) {
            copied_len = 0;
            probe_ret = err;
        }
    }
    if (probe_ret == 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }
    if (!payload_tlv_write_header_direct(
            ptr, payload_offset, PAYLOAD_TLV_KIND_BYTES, 1,
            PAYLOAD_TLV_FLAG_DIRECTION_OUT, user_len, copied_len,
            probe_ret, user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline void emit_mount_query_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    u32 payload_capacity = p->sys_id == SYS_STATMOUNT
        ? STATMOUNT_EXIT_PAYLOAD_CAPACITY : LISTMOUNT_EXIT_PAYLOAD_CAPACITY;
    u32 body_offset = EVENT_V2_HEADER_LEN;
    u32 payload_offset = body_offset + EVENT_V2_EXIT_BODY_LEN;
    u32 out_size = payload_offset + payload_capacity;
    struct bpf_dynptr ptr;
    long reserve_ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (reserve_ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    u16 flags = 0;
    u32 payload_size = p->sys_id == SYS_STATMOUNT
        ? capture_statmount_exit_tlv_direct(&ptr, payload_offset, p, &flags)
        : capture_listmount_ids_tlv_direct(&ptr, payload_offset, p, ret_value, &flags);
    if (payload_size > 0) {
        flags |= EVENT_FLAG_PAYLOAD_TLV;
    }

    struct event_v2_header header = {};
    init_syscall_event_v2_header_direct(
        &header, EVENT_TYPE_EXIT, flags, p->pid, p->tid, p->sys_id,
        out_size, p->enter_time + duration);
    if (bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0) < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    struct syscall_exit_event_v2 body = {};
    init_syscall_exit_event_v2_from_pending(
        &body, p, ret_value, duration, payload_size);
    if (bpf_dynptr_write(&ptr, body_offset, &body, sizeof(body), 0) < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

#endif
