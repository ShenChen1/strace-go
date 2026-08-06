#ifndef STRACE_GO_SYSCALL_MSG_CONTROL_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_MSG_CONTROL_DIRECT_EVENT_V2_H

#define MSGHDR_CONTROL_OFFSET 32
#define MSGHDR_CONTROLLEN_OFFSET 40
#define MSG_DIRECT_CMSG_MAX 256
#define MSG_DIRECT_CMSG_TLV_MAX (PAYLOAD_TLV_HEADER_SIZE + MSG_DIRECT_CMSG_MAX)

struct msg_direct_control {
    u64 ptr;
    u64 len;
};

static __always_inline int msg_direct_read_control(u64 msg_ptr, struct msg_direct_control *control)
{
    control->ptr = 0;
    control->len = 0;
    if (!msg_ptr) {
        return -1;
    }
    if (bpf_probe_read_user(&control->ptr, sizeof(control->ptr), (void *)(msg_ptr + MSGHDR_CONTROL_OFFSET)) < 0) {
        return -1;
    }
    if (bpf_probe_read_user(&control->len, sizeof(control->len), (void *)(msg_ptr + MSGHDR_CONTROLLEN_OFFSET)) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline u32 capture_msg_control_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 tlv_flags,
    u64 msg_ptr,
    u16 *event_flags)
{
    struct msg_direct_control control = {};
    if (msg_direct_read_control(msg_ptr, &control) < 0 || !control.ptr || control.len == 0) {
        return 0;
    }

    u32 user_len = payload_tlv_clamp_u32(control.len);
    u32 copied_len = payload_tlv_copy_len(control.len, MSG_DIRECT_CMSG_MAX);
    s32 probe_ret = 0;
    void *payload_data = bpf_dynptr_data(
        ptr,
        payload_offset + PAYLOAD_TLV_HEADER_SIZE,
        MSG_DIRECT_CMSG_MAX);
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, copied_len, (void *)control.ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (probe_ret == 0 && copied_len > 0 && copied_len < user_len) {
        *event_flags |= EVENT_FLAG_TRUNCATED;
        record_payload_truncated_event();
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_CMSG,
            1,
            tlv_flags,
            user_len,
            copied_len,
            probe_ret,
            control.ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

#endif
