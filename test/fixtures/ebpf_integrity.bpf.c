#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "runtime_abi.h"
#include "runtime_stats.h"
#include "signal_event_v2.h"
#include "lifecycle_event_v2.h"
#include "syscall_event_core_v2.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} test_command SEC(".maps");

enum integrity_test_command {
    EMIT_SIGNAL = 128,
    COPY_FAILURE,
    PENDING_FAILURE,
    PENDING_MISMATCH,
    ORPHAN_EXIT,
    LIFECYCLE_FAILURE,
    PAYLOAD_TRUNCATION,
    EMIT_ENTER,
    EMIT_LIFECYCLE,
    DROP_BEFORE_RESERVE,
    DROP_AFTER_WRITE_FAILURE,
};

static __always_inline void inject_emission_failure(u32 command)
{
    u64 sequence = next_event_sequence();
    if (command == DROP_BEFORE_RESERVE) {
        record_ringbuf_reserve_fail();
        return;
    }
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, EVENT_V2_HEADER_LEN, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &sequence, sizeof(sequence), 0);
    if (ret < 0) record_ringbuf_copy_fail();
    bpf_ringbuf_discard_dynptr(&ptr, 0);
}

SEC("socket")
int integrity_test(struct __sk_buff *skb)
{
    u32 key = 0;
    u32 *command = bpf_map_lookup_elem(&test_command, &key);
    if (!command) return 0;
    switch (*command) {
    case DROP_BEFORE_RESERVE:
    case DROP_AFTER_WRITE_FAILURE:
        inject_emission_failure(*command);
        break;
    case COPY_FAILURE: record_ringbuf_copy_fail(); break;
    case PENDING_FAILURE: record_pending_update_fail(); break;
    case PENDING_MISMATCH: record_pending_mismatch(); break;
    case ORPHAN_EXIT: record_orphan_exit(1, 1, SYS_GETPID, 1, ORPHAN_REASON_NO_PENDING); break;
    case LIFECYCLE_FAILURE: record_lifecycle_map_update_fail(); break;
    case PAYLOAD_TRUNCATION: record_payload_truncated_event(); break;
    case EMIT_ENTER: {
        struct trace_event_raw_sys_enter ctx = {};
        emit_syscall_enter_event_v2_direct(1, 1, SYS_GETPID, &ctx, EVENT_FLAG_GENERIC_ENTER, bpf_ktime_get_ns());
        break;
    }
    case EMIT_LIFECYCLE:
        emit_lifecycle_event_v2_direct(LIFECYCLE_FORK, 1, 1, 1, 2, 0);
        break;
    default: {
        struct signal_event_v2 body = {};
        emit_signal_event_v2(1, 1, &body);
        break;
    }
    }
    return 0;
}
