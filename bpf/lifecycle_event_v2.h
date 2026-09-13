#ifndef STRACE_GO_LIFECYCLE_EVENT_V2_H
#define STRACE_GO_LIFECYCLE_EVENT_V2_H

static __always_inline void init_lifecycle_event_v2_header(
    struct event_v2_header *header,
    u32 pid,
    u32 tid,
    u32 out_size,
    u64 ts_ns)
{
    header->version = EVENT_VERSION;
    header->event_type = EVENT_TYPE_LIFECYCLE;
    header->flags = 0;
    header->header_len = EVENT_V2_HEADER_LEN;
    header->size = out_size;
    header->pid = pid;
    header->tid = tid;
    header->sys_id = 0;
    capture_event_integrity(header);
    header->ts_ns = ts_ns;
    capture_event_v2_comm(header);
}

static __always_inline void init_lifecycle_event_v2_body(
    struct lifecycle_event_v2 *body,
    u32 kind,
    u32 snapshot_len,
    u64 arg0,
    u64 arg1)
{
    body->action = kind;
    body->snapshot_len = snapshot_len;
    body->args[0] = arg0;
    body->args[1] = arg1;
    body->args[2] = 0;
    body->args[3] = 0;
    body->args[4] = 0;
    body->args[5] = 0;
}

static __always_inline void emit_lifecycle_event_v2_direct(
    u32 kind,
    u32 pid,
    u32 tid,
    u64 arg0,
    u64 arg1,
    const void *snapshot_str)
{
    u32 payload_capacity = snapshot_str ? LIFECYCLE_SNAPSHOT_MAX : 0;
    u32 payload_size = 0;
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN + payload_capacity;
    u32 payload_offset = EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN;

    struct bpf_dynptr ptr;
    u64 sequence = next_event_sequence();
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    if (snapshot_str) {
        void *payload = bpf_dynptr_data(&ptr, payload_offset, LIFECYCLE_SNAPSHOT_MAX);
        if (!payload) {
            record_ringbuf_copy_fail();
        } else {
            long n = bpf_probe_read_kernel_str(payload, LIFECYCLE_SNAPSHOT_MAX, snapshot_str);
            if (n > 0) {
                payload_size = (u32)n;
            }
        }
    }

    struct event_v2_header header = {.seq = sequence};
    init_lifecycle_event_v2_header(&header, pid, tid, out_size, bpf_ktime_get_ns());
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct lifecycle_event_v2 body = {};
    init_lifecycle_event_v2_body(&body, kind, payload_size, arg0, arg1);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_lifecycle_event(
    u32 kind,
    u32 pid,
    u32 tid,
    u64 arg0,
    u64 arg1,
    const void *snapshot_str)
{
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !(*cfg & CONFIG_EMIT_LIFECYCLE)) {
        return;
    }

    emit_lifecycle_event_v2_direct(kind, pid, tid, arg0, arg1, snapshot_str);
}

static __always_inline u32 *lookup_lifecycle_task_filter_flags(u32 pid, u32 tid)
{
    u32 *flags = bpf_map_lookup_elem(&filter_map, &pid);
    if (flags && (*flags & FILTER_TASK_TRACKED)) {
        return flags;
    }
    if (tid != pid) {
        flags = bpf_map_lookup_elem(&filter_map, &tid);
        if (flags && (*flags & FILTER_TASK_TRACKED)) {
            return flags;
        }
    }
    return 0;
}

static __always_inline int is_lifecycle_task_tracked(u32 pid, u32 tid)
{
    return lookup_lifecycle_task_filter_flags(pid, tid) != 0;
}

static __always_inline void mark_attach_task_exited(u32 tid)
{
    if (tid == 0) {
        return;
    }
    u32 *root = bpf_map_lookup_elem(&attach_roots_map, &tid);
    if (!root) {
        return;
    }
    u32 value = 1;
    if (bpf_map_update_elem(&attach_exited_map, &tid, &value, BPF_ANY) != 0) {
        record_lifecycle_map_update_fail();
    }
}

#endif
