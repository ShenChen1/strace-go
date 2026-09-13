#ifndef STRACE_GO_SIGNAL_EVENT_V2_H
#define STRACE_GO_SIGNAL_EVENT_V2_H

struct signal_record_v2 {
    struct event_v2_header header;
    struct signal_event_v2 body;
};

static __always_inline void emit_signal_event_v2(
    u32 pid,
    u32 tid,
    const struct signal_event_v2 *body)
{
    u64 sequence = next_event_sequence();
    struct signal_record_v2 *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        record_ringbuf_reserve_fail();
        return;
    }

    event->header.version = EVENT_VERSION;
    event->header.event_type = EVENT_TYPE_SIGNAL;
    event->header.flags = 0;
    event->header.header_len = EVENT_V2_HEADER_LEN;
    event->header.size = sizeof(*event);
    event->header.pid = pid;
    event->header.tid = tid;
    event->header.sys_id = 0;
    event->header.seq = sequence;
    capture_event_integrity(&event->header);
    event->header.ts_ns = bpf_ktime_get_ns();
    capture_event_v2_comm(&event->header);
    event->body = *body;

    bpf_ringbuf_submit(event, 0);
}

#endif
