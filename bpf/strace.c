#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_capture.h"

char LICENSE[] SEC("license") = "GPL";

volatile const u32 SYS_RT_SIGRETURN = 15;
volatile const u32 SYS_RT_SIGRETURN_COMPAT = 173;
volatile const u32 SYS_NANOSLEEP = 35;
volatile const u32 SYS_EXECVE = 59;
volatile const u32 SYS_EXIT = 60;
volatile const u32 SYS_CAPSET = 126;
volatile const u32 SYS_RT_SIGSUSPEND = 130;
volatile const u32 SYS_EXIT_GROUP = 231;
volatile const u32 SYS_EXECVEAT = 322;

#define EXEC_SNAPSHOT_MAGIC 0x45584543
#define EXEC_PATH_SNAPSHOT_MAX 512
#define EXEC_SNAPSHOT_OFFSET 4096
#define EXEC_ARG_MAX 48
#define EXEC_ENV_MAX 64
#define EXEC_ARG_DATA_SIZE 42
#define EVENT_VERSION 2
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_OPENAT 257
#define EVENT_TYPE_ENTER 1
#define EVENT_TYPE_EXIT 2
#define EVENT_TYPE_LIFECYCLE 3
#define EVENT_FLAG_GENERIC_ENTER 1
#define LIFECYCLE_FORK 1
#define LIFECYCLE_EXEC 2
#define LIFECYCLE_EXIT 3
#define LIFECYCLE_FREE 4
#define CONFIG_CAPTURE_STACK 1
#define CONFIG_FOLLOW_FORKS 2
#define CONFIG_EMIT_ENTER 4
#define CONFIG_SYSCALL_FILTER 8
#define CONFIG_SYSCALL_FILTER_NEGATED 16
#define CONFIG_EMIT_LIFECYCLE 32
#define EVENT_V2_HEADER_LEN 40
#define EVENT_V2_ENTER_BODY_LEN 56
#define EVENT_V2_EXIT_BODY_LEN 72
#define EVENT_V2_LIFECYCLE_BODY_LEN 56

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
    u32 sys_id;
    u32 tid;
    u16 event_version;
    u16 event_type;
    u32 event_flags;
    u32 lifecycle_action;
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

#include "payload_tlv.h"

struct pending_syscall {
    u64 enter_time;
    u64 args[6];
    u32 pid;
    u32 sys_id;
    u32 tid;
    s32 stack_id;
};

struct bpf_stats {
    u64 ringbuf_reserve_fail;
    u64 ringbuf_copy_fail;
    u64 payload_truncated_events;
};

struct event_v2_header {
    u16 version;
    u16 event_type;
    u16 flags;
    u16 header_len;
    u32 size;
    u32 pid;
    u32 tid;
    u32 sys_id;
    u64 seq;
    u64 ts_ns;
};

struct syscall_enter_event_v2 {
    u64 args[6];
    u32 capture_len;
    u32 capture_flags;
};

struct syscall_exit_event_v2 {
    s64 ret;
    u64 duration_ns;
    u64 args[6];
    u32 capture_len;
    u32 capture_flags;
};

struct lifecycle_event_v2 {
    u32 action;
    u32 snapshot_len;
    u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct pending_syscall);
} pending_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, u32);
} syscall_filter_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_stats);
} stats_map SEC(".maps");

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

static __always_inline void capture_exec_records(
    struct exec_arg_snapshot *records,
    u64 array,
    u32 max_count,
    u16 *count,
    s32 *status,
    u64 *next)
{
    *count = 0;
    *status = -1;
    *next = array;

    if (!array) {
        *status = 0;
        return;
    }

    for (u32 i = 0; i < EXEC_ENV_MAX; i++) {
        if (i >= max_count) {
            break;
        }

        u64 slot = array + i * sizeof(u64);
        u64 ptr = 0;
        if (bpf_probe_read_user(&ptr, sizeof(ptr), (void *)slot) < 0) {
            *status = -1;
            *next = slot;
            break;
        }
        if (!ptr) {
            *status = 0;
            break;
        }

        struct exec_arg_snapshot *arg = &records[i];
        arg->ptr = ptr;
        arg->data[0] = 0;
        arg->len = bpf_probe_read_user_str(arg->data, sizeof(arg->data), (void *)ptr);
        *count = i + 1;

        if (i == max_count - 1) {
            u64 next_slot = array + max_count * sizeof(u64);
            u64 next_ptr = 0;
            if (bpf_probe_read_user(&next_ptr, sizeof(next_ptr), (void *)next_slot) < 0) {
                *status = -1;
                *next = next_slot;
            } else if (!next_ptr) {
                *status = 0;
            } else {
                *status = 1;
            }
        }
    }
}

static __always_inline void capture_exec_path_tlv(struct bpf_event *e, u32 path_index, u32 path_offset)
{
    u32 path_data_offset = path_offset + PAYLOAD_TLV_HEADER_SIZE;
    u32 path_copied_len = 0;
    s32 path_probe_ret = 0;

    if (!e->args[path_index]) {
        path_probe_ret = -1;
    } else {
        long n = bpf_probe_read_user_str(
            e->str_arg + path_data_offset,
            EXEC_PATH_SNAPSHOT_MAX,
            (void *)e->args[path_index]);
        if (n < 0) {
            path_probe_ret = n;
        } else if (n > EXEC_PATH_SNAPSHOT_MAX) {
            path_copied_len = EXEC_PATH_SNAPSHOT_MAX;
        } else {
            path_copied_len = (u32)n;
        }
    }

    payload_tlv_write_header_at(
        e,
        path_offset,
        PAYLOAD_TLV_KIND_STRING,
        path_index,
        0,
        path_copied_len,
        path_copied_len,
        path_probe_ret,
        e->args[path_index]);

    e->data_len = path_data_offset + path_copied_len;
}

static __always_inline void capture_exec_tlv(struct bpf_event *e, u32 path_index, u32 argv_index, u32 env_index)
{
    struct exec_snapshot *snapshot = (void *)(e->str_arg + PAYLOAD_TLV_HEADER_SIZE);
    u32 path_offset = PAYLOAD_TLV_HEADER_SIZE + sizeof(*snapshot);

    snapshot->header.magic = EXEC_SNAPSHOT_MAGIC;
    capture_exec_path_tlv(e, path_index, path_offset);
    capture_exec_records(
        snapshot->argv,
        e->args[argv_index],
        EXEC_ARG_MAX,
        &snapshot->header.argv_count,
        &snapshot->header.argv_status,
        &snapshot->header.argv_next);
    capture_exec_records(
        snapshot->env,
        e->args[env_index],
        EXEC_ENV_MAX,
        &snapshot->header.env_count,
        &snapshot->header.env_status,
        &snapshot->header.env_next);

    payload_tlv_write_header(
        e,
        PAYLOAD_TLV_KIND_EXEC_ARGS,
        argv_index,
        0,
        sizeof(*snapshot),
        sizeof(*snapshot),
        0,
        e->args[argv_index]);

    e->event_flags |= EVENT_FLAG_PAYLOAD_TLV;
}

static __always_inline void capture_capset_data(struct bpf_event *e)
{
    if (e->sys_id != SYS_CAPSET || !e->args[1]) { // capset
        return;
    }
    if (e->data_len < 8) {
        return;
    }

    u32 version = 0;
    __builtin_memcpy(&version, e->str_arg, sizeof(version));

    u32 size = 0;
    if (version == 0x19980330) {
        size = 12;
    } else if (version == 0x20071026 || version == 0x20080522) {
        size = 24;
    } else {
        return;
    }

    long err = bpf_probe_read_user(e->str_arg + 512, size, (void *) e->args[1]);
    if (err == 0) {
        u32 req_len = 512 + size;
        if (e->data_len < req_len) {
            e->data_len = req_len;
        }
    }
}

static __always_inline void save_pending_syscall(u32 tid, struct bpf_event *e)
{
    struct pending_syscall p;

    p.enter_time = e->enter_time;
    p.args[0] = e->args[0];
    p.args[1] = e->args[1];
    p.args[2] = e->args[2];
    p.args[3] = e->args[3];
    p.args[4] = e->args[4];
    p.args[5] = e->args[5];
    p.pid = e->pid;
    p.sys_id = e->sys_id;
    p.tid = e->tid;
    p.stack_id = e->stack_id;

    bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY);
}

static __always_inline void event_from_pending(struct bpf_event *e, struct pending_syscall *p)
{
    e->pid = p->pid;
    e->sys_id = p->sys_id;
    e->tid = p->tid;
    e->event_version = EVENT_VERSION;
    e->event_type = EVENT_TYPE_EXIT;
    e->event_flags = 0;
    e->lifecycle_action = 0;
    e->probe_ret_enter = -1;
    e->probe_ret_exit = -1;
    e->enter_time = p->enter_time;
    e->duration = 0;
    e->args[0] = p->args[0];
    e->args[1] = p->args[1];
    e->args[2] = p->args[2];
    e->args[3] = p->args[3];
    e->args[4] = p->args[4];
    e->args[5] = p->args[5];
    e->ret = 0;
    e->ptr = 0;
    e->data_len = 0;
    e->stack_id = p->stack_id;
}

static __always_inline int should_trace_syscall(u32 sys_id, u32 *cfg)
{
    if (!cfg || !(*cfg & CONFIG_SYSCALL_FILTER)) {
        return 1;
    }

    u32 *enabled = bpf_map_lookup_elem(&syscall_filter_map, &sys_id);
    if (*cfg & CONFIG_SYSCALL_FILTER_NEGATED) {
        return enabled ? 0 : 1;
    }
    return enabled ? 1 : 0;
}

static __always_inline struct bpf_stats *lookup_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void record_ringbuf_reserve_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->ringbuf_reserve_fail++;
    }
}

static __always_inline void record_ringbuf_copy_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->ringbuf_copy_fail++;
    }
}

static __always_inline void record_payload_truncated_event(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->payload_truncated_events++;
    }
}

static __always_inline u32 event_output_size(struct bpf_event *e)
{
    u32 data_len = e->data_len;
    if (data_len > sizeof(e->str_arg)) {
        data_len = sizeof(e->str_arg);
    }
    return __builtin_offsetof(struct bpf_event, str_arg) + data_len;
}

static __always_inline u32 event_payload_size(struct bpf_event *e)
{
    u32 data_len = e->data_len;
    if (data_len > sizeof(e->str_arg)) {
        data_len = sizeof(e->str_arg);
    }
    return data_len;
}

static __always_inline void emit_legacy_event(struct bpf_event *e)
{
    u32 out_size = event_output_size(e);
    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    ret = bpf_dynptr_write(&ptr, 0, e, out_size, 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void init_event_v2_header(struct event_v2_header *header, struct bpf_event *e, u32 out_size)
{
    header->version = EVENT_VERSION;
    header->event_type = e->event_type;
    header->flags = (u16)e->event_flags;
    header->header_len = EVENT_V2_HEADER_LEN;
    header->size = out_size;
    header->pid = e->pid;
    header->tid = e->tid;
    header->sys_id = e->sys_id;
    header->seq = 0;
    header->ts_ns = e->enter_time;
    if (e->event_type == EVENT_TYPE_EXIT && e->duration > 0) {
        header->ts_ns = e->enter_time + e->duration;
    }
}

static __always_inline void init_syscall_enter_event_v2(struct syscall_enter_event_v2 *body, struct bpf_event *e, u32 payload_size)
{
    body->args[0] = e->args[0];
    body->args[1] = e->args[1];
    body->args[2] = e->args[2];
    body->args[3] = e->args[3];
    body->args[4] = e->args[4];
    body->args[5] = e->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void init_syscall_exit_event_v2(struct syscall_exit_event_v2 *body, struct bpf_event *e, u32 payload_size)
{
    body->ret = e->ret;
    body->duration_ns = e->duration;
    body->args[0] = e->args[0];
    body->args[1] = e->args[1];
    body->args[2] = e->args[2];
    body->args[3] = e->args[3];
    body->args[4] = e->args[4];
    body->args[5] = e->args[5];
    body->capture_len = payload_size;
    body->capture_flags = 0;
}

static __always_inline void init_lifecycle_event_v2(struct lifecycle_event_v2 *body, struct bpf_event *e, u32 payload_size)
{
    body->action = e->lifecycle_action;
    body->snapshot_len = payload_size;
    body->args[0] = e->args[0];
    body->args[1] = e->args[1];
    body->args[2] = e->args[2];
    body->args[3] = e->args[3];
    body->args[4] = e->args[4];
    body->args[5] = e->args[5];
}

static __always_inline void emit_syscall_event_v2(struct bpf_event *e)
{
    u32 payload_size = event_payload_size(e);
    u32 body_size = EVENT_V2_ENTER_BODY_LEN;
    if (e->event_type == EVENT_TYPE_EXIT) {
        body_size = EVENT_V2_EXIT_BODY_LEN;
    }
    u32 out_size = EVENT_V2_HEADER_LEN + body_size + payload_size;

    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {};
    init_event_v2_header(&header, e, out_size);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    if (e->event_type == EVENT_TYPE_EXIT) {
        struct syscall_exit_event_v2 body = {};
        init_syscall_exit_event_v2(&body, e, payload_size);
        ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    } else {
        struct syscall_enter_event_v2 body = {};
        init_syscall_enter_event_v2(&body, e, payload_size);
        ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    }
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    if (payload_size > 0) {
        ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN + body_size, e->str_arg, payload_size, 0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            bpf_ringbuf_discard_dynptr(&ptr, 0);
            return;
        }
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_lifecycle_event_v2(struct bpf_event *e)
{
    u32 payload_size = event_payload_size(e);
    u32 out_size = EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN + payload_size;

    struct bpf_dynptr ptr;
    long ret = bpf_ringbuf_reserve_dynptr(&events, out_size, 0, &ptr);
    if (ret < 0) {
        record_ringbuf_reserve_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct event_v2_header header = {};
    init_event_v2_header(&header, e, out_size);
    ret = bpf_dynptr_write(&ptr, 0, &header, sizeof(header), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    struct lifecycle_event_v2 body = {};
    init_lifecycle_event_v2(&body, e, payload_size);
    ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN, &body, sizeof(body), 0);
    if (ret < 0) {
        record_ringbuf_copy_fail();
        bpf_ringbuf_discard_dynptr(&ptr, 0);
        return;
    }

    if (payload_size > 0) {
        ret = bpf_dynptr_write(&ptr, EVENT_V2_HEADER_LEN + EVENT_V2_LIFECYCLE_BODY_LEN, e->str_arg, payload_size, 0);
        if (ret < 0) {
            record_ringbuf_copy_fail();
            bpf_ringbuf_discard_dynptr(&ptr, 0);
            return;
        }
    }
    bpf_ringbuf_submit_dynptr(&ptr, 0);
}

static __always_inline void emit_event(struct bpf_event *e)
{
    if ((e->event_type == EVENT_TYPE_ENTER || e->event_type == EVENT_TYPE_EXIT) &&
        (e->event_flags & EVENT_FLAG_TRUNCATED)) {
        record_payload_truncated_event();
    }
    if (e->event_type == EVENT_TYPE_ENTER || e->event_type == EVENT_TYPE_EXIT) {
        emit_syscall_event_v2(e);
        return;
    }
    if (e->event_type == EVENT_TYPE_LIFECYCLE) {
        emit_lifecycle_event_v2(e);
        return;
    }
    emit_legacy_event(e);
}

static __always_inline void emit_lifecycle_event(u32 kind, u32 pid, u32 tid, u64 arg0, u64 arg1, const void *snapshot_str)
{
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !(*cfg & CONFIG_EMIT_LIFECYCLE)) {
        return;
    }

    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) {
        return;
    }

    e->pid = pid;
    e->sys_id = 0;
    e->tid = tid;
    e->event_version = EVENT_VERSION;
    e->event_type = EVENT_TYPE_LIFECYCLE;
    e->event_flags = 0;
    e->lifecycle_action = kind;
    e->probe_ret_enter = 0;
    e->probe_ret_exit = 0;
    e->enter_time = bpf_ktime_get_ns();
    e->duration = 0;
    e->args[0] = arg0;
    e->args[1] = arg1;
    e->args[2] = 0;
    e->args[3] = 0;
    e->args[4] = 0;
    e->args[5] = 0;
    e->ret = 0;
    e->ptr = 0;
    e->data_len = 0;
    e->stack_id = -1;
    e->str_arg[0] = 0;

    if (snapshot_str) {
        long n = bpf_probe_read_kernel_str(e->str_arg, 4096, snapshot_str);
        if (n > 0) {
            e->data_len = n;
        }
        e->probe_ret_enter = n;
    }

    emit_event(e);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id == SYS_RT_SIGRETURN || sys_id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;
    
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_syscall(sys_id, cfg)) return 0;
    
    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    
    e->pid = pid; e->sys_id = sys_id; e->tid = tid; e->probe_ret_enter = -1; e->probe_ret_exit = -1; e->ptr = 0; e->ret = 0; e->data_len = 0; e->stack_id = -1;
    e->enter_time = bpf_ktime_get_ns();
    e->duration = 0;

    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        e->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    e->event_version = EVENT_VERSION;
    e->event_type = EVENT_TYPE_EXIT;
    e->event_flags = 0;
    e->lifecycle_action = 0;

    // IMPACT: Revert zero-initialization in trace_sys_enter to restore compile success under BPF.
    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    CAPTURE_ARGS_ENTER(e->sys_id, e);
    capture_openat_tlv(e);
    capture_write_tlv(e);
    capture_capset_data(e);
    if (e->sys_id == SYS_EXECVE) {
        capture_exec_tlv(e, 0, 1, 2);
    } else if (e->sys_id == SYS_EXECVEAT) {
        capture_exec_tlv(e, 1, 2, 3);
    }

    if (cfg && (*cfg & CONFIG_EMIT_ENTER)) {
        u32 saved_flags = e->event_flags;
        e->event_type = EVENT_TYPE_ENTER;
        e->event_flags = saved_flags | EVENT_FLAG_GENERIC_ENTER;
        emit_event(e);
        e->event_type = EVENT_TYPE_EXIT;
        e->event_flags = saved_flags;
    }

    save_pending_syscall(tid, e);

    if (sys_id == SYS_EXIT || sys_id == SYS_EXIT_GROUP) { // exit (60), exit_group (231)
        if (tid == pid) {
            u32 val = 1;
            bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY);
        }
        emit_event(e);
        bpf_map_delete_elem(&pending_syscalls, &tid);
    }

    if (sys_id == SYS_RT_SIGSUSPEND || sys_id == SYS_NANOSLEEP) { // rt_sigsuspend (130), nanosleep (35)
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 nr_threads = 0;
        if (task) {
            nr_threads = BPF_CORE_READ(task, signal, nr_threads);
        }
        if (nr_threads > 1 && tid == pid) {
            e->probe_ret_enter = 3;
            e->event_type = EVENT_TYPE_ENTER;
            emit_event(e);
            e->probe_ret_enter = -1;
            e->event_type = EVENT_TYPE_EXIT;
        }
    }

    if (e->sys_id == SYS_EXECVE || e->sys_id == SYS_EXECVEAT) {
        e->ret = -514;
        u32 *exited = bpf_map_lookup_elem(&main_exited_map, &pid);
        if (exited && *exited == 1) {
            e->probe_ret_enter = 1;
        } else {
            e->probe_ret_enter = 0;
        }
        e->event_type = EVENT_TYPE_ENTER;
        emit_event(e);
        e->event_type = EVENT_TYPE_EXIT;
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
    if (ctx->id == SYS_RT_SIGRETURN || ctx->id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    struct pending_syscall *p = NULL;
    u32 is_pending_lookup = 0;
    u32 pending_tid = 0;
    u32 key = 0;
    
    if (ctx->ret == 0) {
        u32 *p_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (p_tid) {
            pending_tid = *p_tid;
            p = bpf_map_lookup_elem(&pending_syscalls, &pending_tid);
            is_pending_lookup = 1;
        }
    }
    if (!p) {
        p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    }
    if (!p) return 0;

    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    event_from_pending(e, p);
    e->ret = ctx->ret;
    if (e->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > e->enter_time) {
            e->duration = exit_time - e->enter_time;
        }
    }
    
    CAPTURE_ARGS_ENTER(e->sys_id, e);
    capture_write_tlv(e);
    capture_capset_data(e);
    if (e->ret != 0) {
        if (e->sys_id == SYS_EXECVE) {
            capture_exec_tlv(e, 0, 1, 2);
        } else if (e->sys_id == SYS_EXECVEAT) {
            capture_exec_tlv(e, 1, 2, 3);
        }
    }

    CAPTURE_ARGS_EXIT(e->sys_id, e);
    capture_read_tlv(e);
    if (tid == pid && (e->sys_id == SYS_RT_SIGSUSPEND || e->sys_id == SYS_NANOSLEEP)) {
        u32 *pending = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (pending) {
            e->probe_ret_enter = 2;
        }
    }
    
    if (is_pending_lookup) {
        struct pending_syscall *main_p = bpf_map_lookup_elem(&pending_syscalls, &pid);
        if (main_p) {
            e->probe_ret_exit = main_p->sys_id;
        } else {
            e->probe_ret_exit = 0;
        }
        emit_event(e);
        bpf_map_delete_elem(&pending_syscalls, &pending_tid);
        bpf_map_delete_elem(&pending_exec_map, &pid);
        bpf_map_delete_elem(&main_exited_map, &pid);
        if (main_p) {
            bpf_map_delete_elem(&pending_syscalls, &pid);
        }
    } else {
        emit_event(e);
        u32 *pending = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (!(tid == pid && pending)) {
            bpf_map_delete_elem(&pending_syscalls, &tid);
        }
        if ((e->sys_id == SYS_EXECVE || e->sys_id == SYS_EXECVEAT) && tid != pid) {
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
    if (cfg && (*cfg & CONFIG_FOLLOW_FORKS)) {
        u32 val = 1;
        bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);
    }
    emit_lifecycle_event(LIFECYCLE_FORK, parent_pid, parent_pid, parent_pid, child_pid, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    u32 pid = ctx->pid;
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;

    u32 filename_offset = ctx->__data_loc_filename & 0xffff;
    void *filename = 0;
    if (filename_offset > 0) {
        filename = (void *)((char *)ctx + filename_offset);
    }
    emit_lifecycle_event(LIFECYCLE_EXEC, pid, pid, ctx->old_pid, pid, filename);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = ctx->pid;
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;

    bpf_map_delete_elem(&pending_syscalls, &pid);
    bpf_map_delete_elem(&pending_exec_map, &pid);
    bpf_map_delete_elem(&main_exited_map, &pid);
    emit_lifecycle_event(LIFECYCLE_EXIT, pid, pid, pid, 0, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int trace_sched_process_free(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = ctx->pid;
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;

    bpf_map_delete_elem(&pending_syscalls, &pid);
    bpf_map_delete_elem(&pending_exec_map, &pid);
    bpf_map_delete_elem(&main_exited_map, &pid);
    bpf_map_delete_elem(&filter_map, &pid);
    emit_lifecycle_event(LIFECYCLE_FREE, pid, pid, pid, 0, 0);
    return 0;
}
