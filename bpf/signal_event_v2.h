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
    event->header.seq = 0;
    event->header.ts_ns = bpf_ktime_get_ns();
    event->body = *body;

    bpf_ringbuf_submit(event, 0);
}

#endif
