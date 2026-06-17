#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_capture.h"

char LICENSE[] SEC("license") = "GPL";

#define EXEC_SNAPSHOT_MAGIC 0x45584543
#define EXEC_SNAPSHOT_OFFSET 4096
#define EXEC_ARG_MAX 48
#define EXEC_ENV_MAX 64
#define EXEC_ARG_DATA_SIZE 42

struct exec_snapshot_header {
    u32 magic;
    u16 argv_count;
    u16 env_count;
    s32 argv_status;
    s32 env_status;
    u64 argv_next;
    u64 env_next;
};

struct exec_arg_snapshot {
    u64 ptr;
    s32 len;
    u8 data[EXEC_ARG_DATA_SIZE];
    u8 pad[2];
};

struct exec_snapshot {
    struct exec_snapshot_header header;
    struct exec_arg_snapshot argv[EXEC_ARG_MAX];
    struct exec_arg_snapshot env[EXEC_ENV_MAX];
};

struct bpf_event {
    u32 pid;
    u32 sys_id; u32 tid;
    s32 probe_ret_enter; s32 probe_ret_exit;
    u64 enter_time;
    u64 duration;
    u64 args[6];
    s64 ret;
    u64 ptr;
    u32 data_len;
    s32 stack_id;
    u8 str_arg[EXEC_SNAPSHOT_OFFSET + sizeof(struct exec_snapshot)];
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64[127]);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_event);
} heap SEC(".maps");

#ifndef __NR_execve
#define __NR_execve 59
#endif
#ifndef __NR_execveat
#define __NR_execveat 322
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pending_exec_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} main_exited_map SEC(".maps");

static __always_inline void capture_exec_snapshot(struct bpf_event *e, u32 argv_index, u32 env_index)
{
    struct exec_snapshot *snapshot = (void *)(e->str_arg + EXEC_SNAPSHOT_OFFSET);
    snapshot->header.magic = EXEC_SNAPSHOT_MAGIC;
    snapshot->header.argv_count = 0;
    snapshot->header.env_count = 0;
    snapshot->header.argv_status = -1;
    snapshot->header.env_status = -1;
    snapshot->header.argv_next = e->args[argv_index];
    snapshot->header.env_next = e->args[env_index];

    u64 argv = e->args[argv_index];
    if (!argv) {
        snapshot->header.argv_status = 0;
    } else {
        for (u32 i = 0; i < EXEC_ARG_MAX; i++) {
            u64 slot = argv + i * sizeof(u64);
            u64 ptr = 0;
            if (bpf_probe_read_user(&ptr, sizeof(ptr), (void *)slot) < 0) {
                snapshot->header.argv_status = -1;
                snapshot->header.argv_next = slot;
                break;
            }
            if (!ptr) {
                snapshot->header.argv_status = 0;
                break;
            }

            struct exec_arg_snapshot *arg = &snapshot->argv[i];
            arg->ptr = ptr;
            arg->data[0] = 0;
            arg->len = bpf_probe_read_user_str(arg->data, sizeof(arg->data), (void *)ptr);
            snapshot->header.argv_count = i + 1;

            if (i == EXEC_ARG_MAX - 1) {
                u64 next_slot = argv + EXEC_ARG_MAX * sizeof(u64);
                u64 next_ptr = 0;
                if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                    snapshot->header.argv_status = -1;
                    snapshot->header.argv_next = next_slot;
                } else if (!next_ptr) {
                    snapshot->header.argv_status = 0;
                } else {
                    snapshot->header.argv_status = 1;
                }
            }
        }
    }

    u64 envp = e->args[env_index];
    if (!envp) {
        snapshot->header.env_status = 0;
    } else {
        for (u32 i = 0; i < EXEC_ENV_MAX; i++) {
            u64 slot = envp + i * sizeof(u64);
            u64 ptr = 0;
            if (bpf_probe_read_user(&ptr, sizeof(ptr), (void *)slot) < 0) {
                snapshot->header.env_status = -1;
                snapshot->header.env_next = slot;
                break;
            }
            if (!ptr) {
                snapshot->header.env_status = 0;
                break;
            }

            struct exec_arg_snapshot *arg = &snapshot->env[i];
            arg->ptr = ptr;
            arg->data[0] = 0;
            arg->len = bpf_probe_read_user_str(arg->data, sizeof(arg->data), (void *)ptr);
            snapshot->header.env_count = i + 1;

            if (i == EXEC_ENV_MAX - 1) {
                u64 next_slot = envp + EXEC_ENV_MAX * sizeof(u64);
                u64 next_ptr = 0;
                if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                    snapshot->header.env_status = -1;
                    snapshot->header.env_next = next_slot;
                } else if (!next_ptr) {
                    snapshot->header.env_status = 0;
                } else {
                    snapshot->header.env_status = 1;
                }
            }
        }
    }

    u32 snapshot_end = EXEC_SNAPSHOT_OFFSET + sizeof(*snapshot);
    if (e->data_len < snapshot_end) {
        e->data_len = snapshot_end;
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id == 15 || sys_id == 173) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;
    
    u32 key = 0;
    
    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    
    e->pid = pid; e->sys_id = sys_id; e->tid = tid; e->probe_ret_enter = -1; e->probe_ret_exit = -1; e->ptr = 0; e->ret = 0; e->data_len = 0; e->stack_id = -1;
    e->enter_time = bpf_ktime_get_ns();
    e->duration = 0;

    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (cfg && *cfg & 1) {
        e->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }

    // IMPACT: Revert zero-initialization in trace_sys_enter to restore compile success under BPF.
    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    CAPTURE_ARGS_ENTER(e->sys_id, e);
    if (e->sys_id == __NR_execve) {
        capture_exec_snapshot(e, 1, 2);
    } else if (e->sys_id == __NR_execveat) {
        capture_exec_snapshot(e, 2, 3);
    }
    bpf_map_update_elem(&events_map, &tid, e, BPF_ANY);

    if (sys_id == 60 || sys_id == 231) { // exit (60), exit_group (231)
        if (tid == pid) {
            u32 val = 1;
            bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY);
        }
        u32 out_size = __builtin_offsetof(struct bpf_event, str_arg) + e->data_len;
        if (out_size > sizeof(*e)) out_size = sizeof(*e);
        bpf_ringbuf_output(&events, e, out_size, 0);
        bpf_map_delete_elem(&events_map, &tid);
    }

    if (sys_id == 130 || sys_id == 35) { // rt_sigsuspend (130), nanosleep (35)
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 nr_threads = 0;
        if (task) {
            nr_threads = BPF_CORE_READ(task, signal, nr_threads);
        }
        if (nr_threads > 1 && tid == pid) {
            e->probe_ret_enter = 3;
            u32 out_size = __builtin_offsetof(struct bpf_event, str_arg) + e->data_len;
            if (out_size > sizeof(*e)) out_size = sizeof(*e);
            bpf_ringbuf_output(&events, e, out_size, 0);
            e->probe_ret_enter = -1;
        }
    }

    if (e->sys_id == __NR_execve || e->sys_id == __NR_execveat) {
        e->ret = -514;
        u32 *exited = bpf_map_lookup_elem(&main_exited_map, &pid);
        if (exited && *exited == 1) {
            e->probe_ret_enter = 1;
        } else {
            e->probe_ret_enter = 0;
        }
        u32 out_size = __builtin_offsetof(struct bpf_event, str_arg) + e->data_len;
        if (out_size > sizeof(*e)) out_size = sizeof(*e);
        bpf_ringbuf_output(&events, e, out_size, 0);
        if (tid != pid) {
            bpf_map_update_elem(&pending_exec_map, &pid, &tid, BPF_ANY);
        }
    }
    return 0;
}

// IMPACT: Fixed non-leader thread execve exit detection. On successful execve (ret == 0), 
// it looks up via pending_exec_map to find the original thread state, cleaning up the superseded thread.
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id == 15 || ctx->id == 173) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    struct bpf_event *e = NULL;
    u32 is_pending_lookup = 0;
    u32 pending_tid = 0;
    
    if (ctx->ret == 0) {
        u32 *p_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (p_tid) {
            pending_tid = *p_tid;
            e = bpf_map_lookup_elem(&events_map, &pending_tid);
            is_pending_lookup = 1;
        }
    }
    if (!e) {
        e = bpf_map_lookup_elem(&events_map, &tid);
    }
    if (!e) return 0;
    if (tid == pid && (e->sys_id == 130 || e->sys_id == 35)) {
        u32 *pending = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (pending) {
            e->probe_ret_enter = 2;
        }
    }
    e->ret = ctx->ret;
    if (e->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > e->enter_time) {
            e->duration = exit_time - e->enter_time;
        }
    }
    
    CAPTURE_ARGS_EXIT(e->sys_id, e);
    
    if (e->probe_ret_enter < 0) {
        e->probe_ret_enter = -1;
        CAPTURE_ARGS_ENTER(e->sys_id, e);
    }
    
    if (is_pending_lookup) {
        struct bpf_event *main_e = bpf_map_lookup_elem(&events_map, &pid);
        if (main_e) {
            e->probe_ret_exit = main_e->sys_id;
        } else {
            e->probe_ret_exit = 0;
        }
        u32 out_size = __builtin_offsetof(struct bpf_event, str_arg) + e->data_len;
        if (out_size > sizeof(*e)) out_size = sizeof(*e);
        bpf_ringbuf_output(&events, e, out_size, 0);
        bpf_map_delete_elem(&events_map, &pending_tid);
        bpf_map_delete_elem(&pending_exec_map, &pid);
        bpf_map_delete_elem(&main_exited_map, &pid);
        if (main_e) {
            bpf_map_delete_elem(&events_map, &pid);
        }
    } else {
        u32 out_size = __builtin_offsetof(struct bpf_event, str_arg) + e->data_len;
        if (out_size > sizeof(*e)) out_size = sizeof(*e);
        bpf_ringbuf_output(&events, e, out_size, 0);
        u32 *pending = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (!(tid == pid && pending)) {
            bpf_map_delete_elem(&events_map, &tid);
        }
        if ((e->sys_id == __NR_execve || e->sys_id == __NR_execveat) && tid != pid) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
        }
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;
    
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &parent_pid);
    if (!filter_pid) return 0;
    
    u32 cfg_key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg && (*cfg & 2)) {
        u32 val = 1;
        bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);
    }
    return 0;
}
