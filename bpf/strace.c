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
volatile const u32 SYS_CAPGET = 125;
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
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_LSTAT 6
#define SYS_POLL 7
#define SYS_RT_SIGACTION 13
#define SYS_RT_SIGPROCMASK 14
#define SYS_ACCESS 21
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_PIPE 22
#define SYS_SELECT 23
#define SYS_TRUNCATE 76
#define SYS_GETITIMER 36
#define SYS_SETITIMER 38
#define SYS_GETPID 39
#define SYS_SENDFILE 40
#define SYS_SOCKETPAIR 53
#define SYS_UNAME 63
#define SYS_GETCWD 79
#define SYS_CHDIR 80
#define SYS_RENAME 82
#define SYS_MKDIR 83
#define SYS_RMDIR 84
#define SYS_CREAT 85
#define SYS_LINK 86
#define SYS_UNLINK 87
#define SYS_SYMLINK 88
#define SYS_CHMOD 90
#define SYS_CHOWN 92
#define SYS_LCHOWN 94
#define SYS_READLINK 89
#define SYS_GETTIMEOFDAY 96
#define SYS_GETRLIMIT 97
#define SYS_SYSINFO 99
#define SYS_UTIME 132
#define SYS_MKNOD 133
#define SYS_STATFS 137
#define SYS_FSTATFS 138
#define SYS_PRCTL 157
#define SYS_CHROOT 161
#define SYS_ACCT 163
#define SYS_MOUNT 165
#define SYS_UMOUNT2 166
#define SYS_SWAPON 167
#define SYS_SWAPOFF 168
#define SYS_SETXATTR 188
#define SYS_LSETXATTR 189
#define SYS_FSETXATTR 190
#define SYS_GETXATTR 191
#define SYS_LGETXATTR 192
#define SYS_FGETXATTR 193
#define SYS_LISTXATTR 194
#define SYS_LLISTXATTR 195
#define SYS_FLISTXATTR 196
#define SYS_REMOVEXATTR 197
#define SYS_LREMOVEXATTR 198
#define SYS_FREMOVEXATTR 199
#define SYS_ARCH_PRCTL 158
#define SYS_ADJTIMEX 159
#define SYS_SETRLIMIT 160
#define SYS_SETTIMEOFDAY 164
#define SYS_FUTEX 202
#define SYS_IO_SETUP 206
#define SYS_IO_GETEVENTS 208
#define SYS_IO_SUBMIT 209
#define SYS_IO_CANCEL 210
#define SYS_CLOCK_SETTIME 227
#define SYS_CLOCK_GETTIME 228
#define SYS_CLOCK_GETRES 229
#define SYS_CLOCK_NANOSLEEP 230
#define SYS_EPOLL_WAIT 232
#define SYS_EPOLL_CTL 233
#define SYS_UTIMES 235
#define SYS_WAITID 247
#define SYS_ADD_KEY 248
#define SYS_REQUEST_KEY 249
#define SYS_OPENAT 257
#define SYS_MKDIRAT 258
#define SYS_MKNODAT 259
#define SYS_FCHOWNAT 260
#define SYS_FUTIMESAT 261
#define SYS_NEWFSTATAT 262
#define SYS_UNLINKAT 263
#define SYS_RENAMEAT 264
#define SYS_LINKAT 265
#define SYS_SYMLINKAT 266
#define SYS_READLINKAT 267
#define SYS_FCHMODAT 268
#define SYS_FACCESSAT 269
#define SYS_PPOLL 271
#define SYS_GET_ROBUST_LIST 274
#define SYS_UTIMENSAT 280
#define SYS_EPOLL_PWAIT 281
#define SYS_PIPE2 293
#define SYS_PRLIMIT64 302
#define SYS_CLOCK_ADJTIME 305
#define SYS_RENAMEAT2 316
#define SYS_MEMFD_CREATE 319
#define SYS_COPY_FILE_RANGE 326
#define SYS_IO_PGETEVENTS 333
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SYS_FSPICK 433
#define SYS_OPENAT2 437
#define SYS_FACCESSAT2 439
#define SYS_EPOLL_PWAIT2 441
#define SYS_FUTEX_WAITV 449
#define SYS_CACHESTAT 451
#define SYS_FUTEX_WAIT 455
#define SYS_FUTEX_REQUEUE 456
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
#define EVENT_V2_ENTER_BODY_LEN 72
#define EVENT_V2_EXIT_BODY_LEN 72
#define EVENT_V2_LIFECYCLE_BODY_LEN 56
#define LIFECYCLE_SNAPSHOT_MAX 4096

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
    s32 probe_ret_enter; s32 probe_ret_exit;
    u64 enter_time;
    u64 duration;
    u64 args[6];
    s64 ret;
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
    s64 ret;
    s32 probe_ret_enter;
    s32 probe_ret_exit;
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

static __always_inline u32 event_payload_size(struct bpf_event *e)
{
    u32 data_len = e->data_len;
    if (data_len > sizeof(e->str_arg)) {
        data_len = sizeof(e->str_arg);
    }
    return data_len;
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
    header->seq = 0;
    header->ts_ns = ts_ns;
}

static __always_inline void init_syscall_enter_event_v2(struct syscall_enter_event_v2 *body, struct bpf_event *e, u32 payload_size)
{
    body->ret = e->ret;
    body->probe_ret_enter = e->probe_ret_enter;
    body->probe_ret_exit = e->probe_ret_exit;
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

    struct event_v2_header header = {};
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
}

static __always_inline void emit_lifecycle_event(u32 kind, u32 pid, u32 tid, u64 arg0, u64 arg1, const void *snapshot_str)
{
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !(*cfg & CONFIG_EMIT_LIFECYCLE)) {
        return;
    }

    emit_lifecycle_event_v2_direct(kind, pid, tid, arg0, arg1, snapshot_str);
}

#include "syscall_direct_event_v2.h"
#include "syscall_fd_array_direct_event_v2.h"
#include "syscall_getcwd_direct_event_v2.h"
#include "syscall_misc_struct_direct_event_v2.h"
#include "syscall_path_stat_direct_event_v2.h"
#include "syscall_path_direct_event_v2.h"
#include "syscall_openat2_direct_event_v2.h"
#include "syscall_readlink_direct_event_v2.h"
#include "syscall_small_struct_direct_event_v2.h"
#include "syscall_stat_direct_event_v2.h"
#include "syscall_waitid_direct_event_v2.h"
#include "syscall_signal_direct_event_v2.h"
#include "syscall_cachestat_direct_event_v2.h"
#include "syscall_capability_direct_event_v2.h"
#include "syscall_memfd_direct_event_v2.h"
#include "syscall_prctl_direct_event_v2.h"
#include "syscall_key_direct_event_v2.h"
#include "syscall_xattr_direct_event_v2.h"
#include "syscall_fs_direct_event_v2.h"
#include "syscall_aio_getevents_direct_event_v2.h"
#include "syscall_aio_direct_event_v2.h"
#include "syscall_poll_direct_event_v2.h"
#include "syscall_select_direct_event_v2.h"
#include "syscall_epoll_direct_event_v2.h"
#include "syscall_file_time_direct_event_v2.h"
#include "syscall_time_direct_event_v2.h"
#include "syscall_futex_direct_event_v2.h"
#include "syscall_sleep_direct_event_v2.h"
#include "syscall_timex_direct_event_v2.h"

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

    u64 enter_time = bpf_ktime_get_ns();
    s32 stack_id = -1;
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }

    // IMPACT: terminating syscalls synthesize their exit event at enter time without touching the bpf_event carrier.
    if (is_terminating_direct_syscall(sys_id)) {
        if (tid == pid) {
            u32 val = 1;
            bpf_map_update_elem(&main_exited_map, &pid, &val, BPF_ANY);
        }
        emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
        emit_terminating_exit_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        return 0;
    }

    // IMPACT: exec direct events preserve restart/resume status while copying argv/envp/path straight into ringbuf TLV.
    if (is_exec_payload_direct_syscall(sys_id)) {
        s32 probe_ret_enter = 0;
        u32 *exited = bpf_map_lookup_elem(&main_exited_map, &pid);
        if (exited && *exited == 1) {
            probe_ret_enter = 1;
        }
        emit_exec_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time, probe_ret_enter);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        if (tid != pid) {
            bpf_map_update_elem(&pending_exec_map, &pid, &tid, BPF_ANY);
        }
        return 0;
    }

    // IMPACT: path stat syscalls carry an IN path snapshot on enter and an OUT struct on exit without the bpf_event carrier.
    if (is_path_stat_direct_syscall(sys_id)) {
        emit_path_stat_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: simple path-only syscalls snapshot IN paths directly into TLV sections without the fixed-window carrier.
    if (is_path_only_direct_syscall(sys_id)) {
        emit_path_only_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: dual path syscalls snapshot both IN paths directly into TLV sections without the fixed-window carrier.
    if (is_dual_path_direct_syscall(sys_id)) {
        emit_dual_path_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: openat2 snapshots path and struct open_how as direct TLV sections without the fixed-window carrier.
    if (is_openat2_direct_syscall(sys_id)) {
        emit_openat2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: readlink syscalls carry an IN path snapshot on enter and an OUT bytes snapshot on exit without the bpf_event carrier.
    if (is_readlink_direct_syscall(sys_id)) {
        emit_readlink_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: misc struct IN payloads are snapped at enter and later merged with exit-side OUT sections in Go.
    if (is_misc_struct_enter_direct_syscall(sys_id)) {
        emit_misc_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: small pointer/word syscalls snapshot offset words directly into TLV sections without the fixed str_arg window.
    if (is_small_struct_enter_direct_syscall(sys_id)) {
        emit_small_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: itimer set calls snapshot the new timer value at enter and merge old value snapshots at exit.
    if (is_itimer_enter_direct_syscall(sys_id)) {
        emit_itimer_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: time setter syscalls snapshot IN time structs directly into TLV sections at enter.
    if (is_time_struct_enter_direct_syscall(sys_id)) {
        emit_time_struct_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: signal syscalls snapshot sigset/sigaction structs through direct TLV sections and preserve sigsuspend markers.
    if (is_signal_enter_direct_syscall(sys_id)) {
        emit_signal_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, -1);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        if (sys_id == SYS_RT_SIGSUSPEND && should_emit_signal_sigsuspend_marker(tid, pid)) {
            emit_signal_sigsuspend_marker_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        }
        return 0;
    }

    // IMPACT: file timestamp syscalls snapshot path and IN time arrays through direct TLV sections.
    if (is_file_time_direct_syscall(sys_id)) {
        emit_file_time_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: sleep syscalls snapshot request timespecs at enter and remaining timespecs on interrupted exit.
    if (sys_id == SYS_NANOSLEEP) {
        emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], -1);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        if (should_emit_nanosleep_suspended_marker(tid, pid)) {
            emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 0, ctx->args[0], 3);
        }
        return 0;
    }
    if (sys_id == SYS_CLOCK_NANOSLEEP) {
        emit_sleep_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time, 2, ctx->args[2], -1);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: futex timeout snapshots are captured at enter as direct TLV sections, without the fixed-window carrier.
    if (sys_id == SYS_FUTEX) {
        emit_futex_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_WAIT) {
        emit_futex_wait_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_WAITV) {
        emit_futex_waitv_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    if (sys_id == SYS_FUTEX_REQUEUE) {
        emit_futex_requeue_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: cachestat snapshots range at enter and stats at successful exit through direct TLV sections.
    if (sys_id == SYS_CACHESTAT) {
        emit_cachestat_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: capability syscalls snapshot header/data through direct TLV sections without the fixed-window carrier.
    if (is_capability_direct_syscall(sys_id)) {
        emit_capability_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: memfd_create snapshots arg0 name as a direct string TLV without the fixed-window carrier.
    if (is_memfd_create_direct_syscall(sys_id)) {
        emit_memfd_create_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: prctl name/getter payloads are captured through option-aware direct TLV sections.
    if (is_prctl_direct_syscall(sys_id)) {
        emit_prctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: key syscalls snapshot IN strings/bytes directly into TLV sections without the fixed-window carrier.
    if (is_key_direct_syscall(sys_id)) {
        emit_key_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: xattr syscalls snapshot IN strings/bytes and merge positive OUT bytes through direct TLV sections.
    if (is_xattr_direct_syscall(sys_id)) {
        emit_xattr_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: filesystem payload syscalls snapshot strings/bytes directly into TLV sections without the fixed-window carrier.
    if (is_fs_direct_syscall(sys_id)) {
        emit_fs_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: AIO direct syscalls emit bounded TLV sections without the fixed-window carrier.
    if (is_aio_direct_syscall(sys_id)) {
        emit_aio_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: poll/ppoll snapshot pollfd arrays and ppoll timeout through direct TLV sections.
    if (is_poll_direct_syscall(sys_id)) {
        emit_poll_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: select snapshots fd_set/timeval payloads through direct TLV sections without the fixed-window carrier.
    if (is_select_direct_syscall(sys_id)) {
        emit_select_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: epoll_ctl snapshots arg3 event at enter through direct TLV without the fixed-window carrier.
    if (is_epoll_ctl_direct_syscall(sys_id)) {
        emit_epoll_ctl_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: epoll_pwait2 snapshots its timeout at enter and ready events at exit through direct TLV sections.
    if (is_epoll_pwait2_direct_syscall(sys_id)) {
        emit_epoll_pwait2_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: no-payload direct syscalls bypass the large bpf_event carrier while preserving args/ret pairing.
    if (is_scalar_direct_syscall(sys_id) || is_exit_payload_direct_syscall(sys_id) ||
        is_fd_array_direct_syscall(sys_id) ||
        is_getcwd_direct_syscall(sys_id) ||
        is_time_struct_direct_syscall(sys_id) || is_stat_struct_direct_syscall(sys_id) ||
        is_waitid_direct_syscall(sys_id) ||
        is_misc_struct_direct_syscall(sys_id) || is_small_struct_direct_syscall(sys_id)) {
        emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }

    // IMPACT: payload direct syscalls copy IN sections directly into ringbuf TLV storage at syscall enter.
    if (is_payload_direct_syscall(sys_id)) {
        emit_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, enter_time);
        save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
        return 0;
    }
    
    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    
    e->pid = pid; e->sys_id = sys_id; e->tid = tid; e->probe_ret_enter = -1; e->probe_ret_exit = -1; e->ret = 0; e->data_len = 0; e->stack_id = -1;
    e->enter_time = enter_time;
    e->duration = 0;
    e->stack_id = stack_id;
    e->event_version = EVENT_VERSION;
    e->event_type = EVENT_TYPE_EXIT;
    e->event_flags = 0;

    // IMPACT: Revert zero-initialization in trace_sys_enter to restore compile success under BPF.
    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    CAPTURE_ARGS_ENTER(e->sys_id, e);

    if (cfg && (*cfg & CONFIG_EMIT_ENTER)) {
        u32 saved_flags = e->event_flags;
        e->event_type = EVENT_TYPE_ENTER;
        e->event_flags = saved_flags | EVENT_FLAG_GENERIC_ENTER;
        emit_event(e);
        e->event_type = EVENT_TYPE_EXIT;
        e->event_flags = saved_flags;
    }

    save_pending_syscall(tid, e);

    return 0;
}

// IMPACT: Fixed non-leader thread execve exit detection. On successful execve (ret == 0), 
// it looks up via pending_exec_map to find the original thread state, cleaning up the superseded thread.
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id == SYS_RT_SIGRETURN || ctx->id == SYS_RT_SIGRETURN_COMPAT) return 0;
    s64 ret_value = ctx->ret;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    
    struct pending_syscall *p = NULL;
    u32 is_pending_lookup = 0;
    u32 pending_tid = 0;
    u32 key = 0;
    
    if (ret_value == 0) {
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

    // IMPACT: direct exits no longer rebuild a bpf_event from pending metadata before ringbuf output.
    if (is_sys_exit_direct_syscall(p->sys_id)) {
        u64 duration = 0;
        if (p->enter_time > 0) {
            u64 exit_time = bpf_ktime_get_ns();
            if (exit_time > p->enter_time) {
                duration = exit_time - p->enter_time;
            }
        }
        if (is_exit_payload_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_payload_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_gettimeofday_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_gettimeofday_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_clock_time_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_time_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_itimer_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_itimer_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_timex_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_timex_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_sleep_direct_syscall(p->sys_id)) {
            emit_sleep_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_stat_struct_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_stat_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_waitid_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_waitid_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_signal_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_signal_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_getcwd_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_getcwd_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_readlink_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_readlink_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_fd_array_direct_syscall(p->sys_id) && ret_value == 0) {
            emit_fd_array_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_path_only_direct_syscall(p->sys_id)) {
            emit_path_only_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_misc_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_misc_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_small_struct_exit_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_small_struct_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_cachestat_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_cachestat_exit_event_v2_direct(p, ret_value, duration);
        } else if (p->sys_id == SYS_CAPGET && ret_value >= 0) {
            emit_capability_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_prctl_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_prctl_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_aio_getevents_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_aio_getevents_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_aio_setup_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_aio_setup_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_poll_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_poll_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_select_direct_syscall(p->sys_id) && ret_value >= 0) {
            emit_select_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_epoll_wait_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_epoll_wait_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_exec_payload_direct_syscall(p->sys_id) && ret_value != 0) {
            emit_exec_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_xattr_get_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_xattr_get_exit_event_v2_direct(p, ret_value, duration);
        } else if (is_xattr_list_direct_syscall(p->sys_id) && ret_value > 0) {
            emit_xattr_list_exit_event_v2_direct(p, ret_value, duration);
        } else {
            emit_syscall_exit_event_v2_direct(p, ret_value, duration, 0);
        }
        u32 delete_tid = tid;
        if (is_pending_lookup) {
            delete_tid = pending_tid;
        }
        u32 cleanup_nonleader_exec = is_exec_payload_direct_syscall(p->sys_id) && p->tid != p->pid;
        bpf_map_delete_elem(&pending_syscalls, &delete_tid);
        if (is_pending_lookup) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
            bpf_map_delete_elem(&main_exited_map, &pid);
            bpf_map_delete_elem(&pending_syscalls, &pid);
        } else if (cleanup_nonleader_exec) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
        }
        return 0;
    }

    struct bpf_event *e = bpf_map_lookup_elem(&heap, &key);
    if (!e) return 0;
    event_from_pending(e, p);
    e->ret = ret_value;
    if (e->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > e->enter_time) {
            e->duration = exit_time - e->enter_time;
        }
    }
    
    CAPTURE_ARGS_ENTER(e->sys_id, e);

    CAPTURE_ARGS_EXIT(e->sys_id, e);
    if (tid == pid && e->sys_id == SYS_RT_SIGSUSPEND) {
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
