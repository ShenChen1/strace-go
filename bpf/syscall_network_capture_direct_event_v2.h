#ifndef STRACE_GO_SYSCALL_NETWORK_CAPTURE_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_CAPTURE_DIRECT_EVENT_V2_H

#define NETWORK_DIRECT_BYTES_MAX 512
#define NETWORK_DIRECT_SOCKADDR_MAX 128
#define NETWORK_DIRECT_SOCKLEN_SIZE 4
#define NETWORK_DIRECT_SOCKOPT_MAX NETWORK_DIRECT_BYTES_MAX
#define NETWORK_DIRECT_SENDTO_ENTER_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_BYTES_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKADDR_MAX)
#define NETWORK_DIRECT_RECVFROM_EXIT_MAX \
    (PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_BYTES_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKADDR_MAX + \
     PAYLOAD_TLV_HEADER_SIZE + NETWORK_DIRECT_SOCKLEN_SIZE)

struct network_tlv_capture_request {
    struct bpf_dynptr *ptr;
    u32 payload_offset;
    u16 kind;
    u16 arg_index;
    u16 tlv_flags;
    u64 user_ptr;
    u32 user_len;
    u32 copy_len;
    u32 storage_max;
    u16 *event_flags;
};

struct network_socklen_capture_request {
    struct bpf_dynptr *ptr;
    u32 payload_offset;
    u16 arg_index;
    u16 tlv_flags;
    u64 user_ptr;
    u32 *value;
};

static __always_inline u32 network_direct_min_u32(u32 a, u32 b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static __always_inline u32 network_direct_sockopt_len(u64 value)
{
    s32 length = (s32)(u32)value;
    if (length <= 0) {
        return 0;
    }
    return (u32)length;
}

static __always_inline int network_direct_sockopt_fixed_int(
    u64 level_value,
    u64 option_value)
{
    u32 level = (u32)level_value;
    u32 option = (u32)option_value;
    if (level == 270) {
        return option != 9;
    }
    if (level != 1) {
        return 0;
    }
    return option == 1 || option == 2 || option == 5 || option == 6 ||
        option == 7 || option == 8 || option == 9 || option == 10 ||
        option == 11 || option == 12 || option == 14 || option == 15 ||
        option == 16 || option == 18 || option == 19 || option == 27 ||
        option == 29 || option == 30 || option == 32 || option == 33 ||
        option == 34 || option == 35 || option == 36 || option == 37 ||
        option == 40 || option == 41 || option == 42 || option == 43 ||
        option == 44 || option == 45 || option == 46 || option == 49 ||
        option == 53 || option == 56 || option == 60 || option == 63 ||
        option == 64 || option == 65 || option == 68 || option == 69 ||
        option == 70 || option == 73 || option == 74 || option == 75 ||
        option == 76 || option == 80 || option == 82 || option == 83 ||
        option == 84;
}

static __always_inline int network_direct_sockopt_membership_array(
    u64 level_value,
    u64 option_value)
{
    return (u32)level_value == 270 && (u32)option_value == 9;
}

static __always_inline u32 network_direct_sockopt_payload_len(
    u64 level_value,
    u64 option_value,
    u64 optlen_value)
{
    u32 length = network_direct_sockopt_len(optlen_value);
    if (network_direct_sockopt_membership_array(level_value, option_value)) {
        return length & ~3U;
    }
    if (network_direct_sockopt_fixed_int(level_value, option_value) && length > 4) {
        return 4;
    }
    return length;
}

static __always_inline int network_direct_read_socklen(u64 user_ptr, u32 *value)
{
    *value = 0;
    if (!user_ptr) {
        return -1;
    }
    long err = bpf_probe_read_user(value, NETWORK_DIRECT_SOCKLEN_SIZE, (void *)user_ptr);
    if (err < 0) {
        return err;
    }
    return 0;
}

static __always_inline void *network_direct_payload_data(
    struct bpf_dynptr *ptr,
    u32 data_offset,
    u32 max)
{
    if (max == NETWORK_DIRECT_BYTES_MAX) {
        return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_BYTES_MAX);
    }
    if (max == NETWORK_DIRECT_SOCKADDR_MAX) {
        return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_SOCKADDR_MAX);
    }
    return bpf_dynptr_data(ptr, data_offset, NETWORK_DIRECT_SOCKLEN_SIZE);
}

static __always_inline u32 capture_network_tlv_direct(
    struct network_tlv_capture_request *request)
{
    if (request->user_len == 0 || !request->user_ptr) {
        return 0;
    }

    u32 copied_len = network_direct_min_u32(request->copy_len, request->storage_max);
    copied_len = network_direct_min_u32(copied_len, request->user_len);
    s32 probe_ret = 0;
    u32 data_offset = request->payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = network_direct_payload_data(request->ptr, data_offset, request->storage_max);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)request->user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < request->user_len) {
        *request->event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            request->ptr,
            request->payload_offset,
            request->kind,
            request->arg_index,
            request->tlv_flags,
            request->user_len,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_network_socklen_tlv_direct(
    struct network_socklen_capture_request *request)
{
    if (!request->user_ptr) {
        return 0;
    }

    s32 probe_ret = network_direct_read_socklen(request->user_ptr, request->value);
    u32 copied_len = probe_ret == 0 ? NETWORK_DIRECT_SOCKLEN_SIZE : 0;
    if (copied_len > 0) {
        long ret = bpf_dynptr_write(
            request->ptr,
            request->payload_offset + PAYLOAD_TLV_HEADER_SIZE,
            request->value,
            NETWORK_DIRECT_SOCKLEN_SIZE,
            0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            probe_ret = ret;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            request->ptr,
            request->payload_offset,
            PAYLOAD_TLV_KIND_BYTES,
            request->arg_index,
            request->tlv_flags,
            NETWORK_DIRECT_SOCKLEN_SIZE,
            copied_len,
            probe_ret,
            request->user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
