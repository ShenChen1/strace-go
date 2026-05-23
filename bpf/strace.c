#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_capture.h"

char LICENSE[] SEC("license") = "GPL";

// IMPACT: Enlarged str_arg buffer to 4104 bytes to support capturing full PATH_MAX (4096) plus 1 null byte for boundary detection.
struct bpf_event {
    u32 pid;
    u32 sys_id; u32 tid;
    s32 probe_ret_enter; s32 probe_ret_exit;
    u64 args[6];
    u64 ret;
    u64 ptr; 
    u8 str_arg[4104];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct bpf_event);
} events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_event);
} heap SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    if (ctx->id == 15 || ctx->id == 173) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u32 key = 0;
    
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &key);
    if (!filter_pid || *filter_pid != pid) return 0;
    
    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    
    e->pid = pid; e->sys_id = (u32)ctx->id; e->tid = tid; e->probe_ret_enter = -1; e->probe_ret_exit = -1; e->ptr = 0; e->ret = 0;
    
    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    CAPTURE_ARGS_ENTER(e->sys_id, e);
    bpf_map_update_elem(&events_map, &tid, e, BPF_ANY);

#ifndef __NR_execve
#define __NR_execve 59
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif

    if (e->sys_id == __NR_execve || e->sys_id == __NR_execveat) {
        if (tid != pid) {
            bpf_map_update_elem(&events_map, &pid, e, BPF_ANY);
        }
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id == 15 || ctx->id == 173) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct bpf_event *e = bpf_map_lookup_elem(&events_map, &tid);
    if (!e) return 0;
    e->ret = ctx->ret;
    
    CAPTURE_ARGS_EXIT(e->sys_id, e);
    
    if (e->probe_ret_enter < 0) {
        CAPTURE_ARGS_ENTER(e->sys_id, e);
    }
    
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    bpf_map_delete_elem(&events_map, &tid);

    if (e->sys_id == 59 || e->sys_id == 322) {
        if (e->tid != e->pid) {
            u32 other_key = (tid == e->pid) ? e->tid : e->pid;
            bpf_map_delete_elem(&events_map, &other_key);
        }
    }
    return 0;
}
