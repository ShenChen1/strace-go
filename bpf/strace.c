//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid; u32 tid; u32 sys_id; u32 pad0;
    u64 args[6]; u64 ret; u8 is_exit; u8 pad1[7];
    char str_arg[2048];
    u64 ptr;
} __attribute__((aligned(8)));

#include "syscall_capture.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // tid
    __type(value, struct event);
} events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} heap SEC(".maps");

static __always_inline int is_target(u32 pid) {
    u32 zero = 0;
    u32 *target_pid = bpf_map_lookup_elem(&filter_map, &zero);
    if (!target_pid || *target_pid == 0) return 0;
    if (pid == *target_pid) return 1;
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (!is_target(pid)) return 0;

    u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&heap, &zero);
    if (!e) return 0;

    e->pid = pid; e->tid = tid; e->sys_id = ctx->id;
    e->args[0] = ctx->args[0]; e->args[1] = ctx->args[1]; e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3]; e->args[4] = ctx->args[4]; e->args[5] = ctx->args[5];
    e->ret = 0; e->is_exit = 0; e->ptr = 0; e->str_arg[0] = 0; e->pad0 = 0;

    CAPTURE_ARGS(ctx->id, e);

    bpf_map_update_elem(&events_map, &tid, e, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;

    struct event *e_enter = bpf_map_lookup_elem(&events_map, &tid);
    if (!e_enter) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { bpf_map_delete_elem(&events_map, &tid); return 0; }

    e->pid = e_enter->pid; e->tid = e_enter->tid; e->sys_id = e_enter->sys_id;
    e->args[0] = e_enter->args[0]; e->args[1] = e_enter->args[1]; e->args[2] = e_enter->args[2];
    e->args[3] = e_enter->args[3]; e->args[4] = e_enter->args[4]; e->args[5] = e_enter->args[5];
    e->ptr = e_enter->ptr; e->pad0 = e_enter->pad0;

    e->ret = ctx->ret;
    e->is_exit = 1;

    // Use loop to safely copy map memory, Verifier accepts this for small bounds
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        e->str_arg[i] = e_enter->str_arg[i];
    }

    if (e->sys_id == 0 && e->ptr != 0 && (int)e->ret > 0) {
        bpf_probe_read_user(e->str_arg, 2048, (void *)e->ptr);
    }

    // THROTTLE: If it's a large write or read, stop the process so Go can read memory
    if ((e->sys_id == 1 || e->sys_id == 0) && (int)e->ret > 2048) {
        bpf_send_signal(19); // SIGSTOP
    }

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&events_map, &tid);
    return 0;
}
