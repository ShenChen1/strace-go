#ifndef STRACE_GO_EVENT_INTEGRITY_H
#define STRACE_GO_EVENT_INTEGRITY_H

/* CPU-local atomic allocation tolerates nested producers, but does not order reservations. */
static __always_inline u64 next_event_sequence(void)
{
    struct bpf_stats *stats = lookup_stats();
    return stats ? __sync_fetch_and_add(&stats->event_seq, 1) + 1 : 0;
}

/* A global subprogram is verified once, even with many capture failure branches. */
__noinline int record_event_integrity_loss(void)
{
    u64 now = bpf_ktime_get_ns();
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        __sync_val_compare_and_swap(&stats->integrity_first_time_ns, 0, now);
    }
    u32 key = 0;
    struct event_loss_state *loss = bpf_map_lookup_elem(&event_loss_map, &key);
    if (loss) {
        __sync_val_compare_and_swap(&loss->first_time_ns, 0, now);
        __sync_fetch_and_add(&loss->epoch, 1);
    }
    return 0;
}

static __always_inline void capture_event_integrity(struct event_v2_header *header)
{
    header->cpu = bpf_get_smp_processor_id();
    header->reserved = 0;
    header->loss_epoch = 0;
    header->loss_time_ns = 0;
    u32 key = 0;
    struct event_loss_state *loss = bpf_map_lookup_elem(&event_loss_map, &key);
    if (loss) {
        header->loss_epoch = *(volatile u64 *)&loss->epoch;
        header->loss_time_ns = *(volatile u64 *)&loss->first_time_ns;
    }
}

#endif
