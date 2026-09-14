#ifndef STRACE_GO_UNSUPPORTED_ABI_H
#define STRACE_GO_UNSUPPORTED_ABI_H

#include "native_task_abi.h"

static __always_inline int reject_unsupported_syscall_abi(u32 pid, u32 tid, u32 sys_id)
{
    if (current_syscall_has_native_abi(sys_id)) return 0;

    clear_pending_task_state();
    bpf_map_delete_elem(&pending_exec_map, &pid);
    struct event_v2_header header = {.seq = next_event_sequence()};
    init_lifecycle_event_v2_header(&header, pid, tid, sizeof(header), bpf_ktime_get_ns());
    header.event_type = EVENT_TYPE_UNSUPPORTED_ABI;
    header.sys_id = sys_id;
    if (bpf_ringbuf_output(&events, &header, sizeof(header), 0) < 0) {
        record_ringbuf_reserve_fail();
    }
    return 1;
}

#endif
