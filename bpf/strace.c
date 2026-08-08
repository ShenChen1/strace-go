#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_POLL 7
#define SYS_RT_SIGACTION 13
#define SYS_RT_SIGPROCMASK 14
#define SYS_IOCTL 16
#define SYS_ACCESS 21
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_PREAD64 17
#define SYS_PWRITE64 18
#define SYS_PIPE 22
#define SYS_SELECT 23
#define SYS_TRUNCATE 76
#define SYS_GETITIMER 36
#define SYS_SETITIMER 38
#define SYS_GETPID 39
#define SYS_SENDFILE 40
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_SENDMSG 46
#define SYS_RECVMSG 47
#define SYS_BIND 49
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SOCKETPAIR 53
#define SYS_UNAME 63
#define SYS_FCNTL 72
#define SYS_GETCWD 79
#define SYS_CHDIR 80
#define SYS_FCHDIR 81
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
#define SYS_GETDENTS64 217
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
#define SYS_VMSPLICE 278
#define SYS_EPOLL_PWAIT 281
#define SYS_ACCEPT4 288
#define SYS_PIPE2 293
#define SYS_DUP3 292
#define SYS_PREADV 295
#define SYS_PWRITEV 296
#define SYS_RECVMMSG 299
#define SYS_PRLIMIT64 302
#define SYS_CLOCK_ADJTIME 305
#define SYS_SENDMMSG 307
#define SYS_PROCESS_VM_READV 310
#define SYS_PROCESS_VM_WRITEV 311
#define SYS_RENAMEAT2 316
#define SYS_MEMFD_CREATE 319
#define SYS_BPF 321
#define SYS_COPY_FILE_RANGE 326
#define SYS_PREADV2 327
#define SYS_PWRITEV2 328
#define SYS_IO_PGETEVENTS 333
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SYS_FSPICK 433
#define SYS_CLONE3 435
#define SYS_OPENAT2 437
#define SYS_FACCESSAT2 439
#define SYS_PROCESS_MADVISE 440
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
#define CONFIG_FD_STATE 64
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

#include "payload_tlv.h"

struct pending_syscall {
    u64 enter_time;
    u64 args[6];
    u32 pid;
    u32 sys_id;
    u32 tid;
    s32 stack_id;
    u32 aux0;
    u32 aux1;
};

struct bpf_stats {
    u64 ringbuf_reserve_fail;
    u64 ringbuf_copy_fail;
    u64 payload_truncated_events;
    u64 pending_update_fail;
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
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 48);
    __type(key, u32);
    __type(value, u32);
} enter_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u32);
} exit_progs SEC(".maps");

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
} arm_fork_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pre_exec_map SEC(".maps");

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

static __always_inline int is_fd_state_direct_syscall(u32 sys_id)
{
    switch (sys_id) {
    case SYS_OPEN:
    case SYS_OPENAT:
    case SYS_OPENAT2:
    case SYS_CREAT:
    case SYS_CLOSE:
    case SYS_DUP:
    case SYS_DUP2:
    case SYS_DUP3:
    case SYS_CHDIR:
    case SYS_FCHDIR:
    case SYS_FACCESSAT:
    case SYS_FACCESSAT2:
    case SYS_FCHMODAT:
    case SYS_MKDIRAT:
    case SYS_NEWFSTATAT:
    case SYS_FSTAT:
        return 1;
    default:
        return 0;
    }
}

// IMPACT: when a -P path filter is active, fd-state syscalls must keep flowing
// through the ringbuf even if excluded from the trace set, so the Go side can
// maintain a deterministic fd -> path map instead of racy live /proc reads.
static __always_inline int is_fd_state_tracked(u32 sys_id, u32 *cfg)
{
    return cfg && (*cfg & CONFIG_FD_STATE) && is_fd_state_direct_syscall(sys_id);
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

static __always_inline void record_pending_update_fail(void)
{
    struct bpf_stats *stats = lookup_stats();
    if (stats) {
        stats->pending_update_fail++;
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

static __always_inline void emit_lifecycle_event(u32 kind, u32 pid, u32 tid, u64 arg0, u64 arg1, const void *snapshot_str)
{
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !(*cfg & CONFIG_EMIT_LIFECYCLE)) {
        return;
    }

    emit_lifecycle_event_v2_direct(kind, pid, tid, arg0, arg1, snapshot_str);
}

static __always_inline int is_lifecycle_task_tracked(u32 pid, u32 tid)
{
    if (bpf_map_lookup_elem(&filter_map, &pid)) {
        return 1;
    }
    if (tid != pid && bpf_map_lookup_elem(&filter_map, &tid)) {
        return 1;
    }
    return 0;
}

// Lifecycle cleanup is split by ownership: pending state is TID-scoped, while
// exec/main/filter state is process-scoped unless a child thread owns it.
static __always_inline void clear_lifecycle_task_state(u32 pid, u32 tid)
{
    bpf_map_delete_elem(&pending_syscalls, &tid);
    bpf_map_delete_elem(&pre_exec_map, &tid);

    if (tid != pid) {
        u32 *pending_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (pending_tid && *pending_tid == tid) {
            bpf_map_delete_elem(&pending_exec_map, &pid);
        }
        bpf_map_delete_elem(&filter_map, &tid);
        return;
    }

    bpf_map_delete_elem(&pending_exec_map, &pid);
    bpf_map_delete_elem(&main_exited_map, &pid);
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
#include "syscall_clone3_direct_event_v2.h"
#include "syscall_bpf_direct_event_v2.h"
#include "syscall_iovec_direct_event_v2.h"
#include "syscall_iovec_base_exit_direct_event_v2.h"
#include "syscall_msg_direct_event_v2.h"
#include "syscall_fcntl_direct_event_v2.h"
#include "syscall_ioctl_direct_event_v2.h"
#include "syscall_network_direct_event_v2.h"
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
#include "enter_dispatch.h"
#include "exit_dispatch.h"

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 sys_id = (u32)ctx->id;
    if (sys_id == SYS_RT_SIGRETURN || sys_id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (!filter_pid) return 0;

    u32 *pre_exec = bpf_map_lookup_elem(&pre_exec_map, &pid);
    if (pre_exec && !is_exec_payload_direct_syscall(sys_id)) {
        return 0;
    }
    u32 key = 0;
    u32 *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!should_trace_syscall(sys_id, cfg) && !is_fd_state_tracked(sys_id, cfg)) return 0;

    u64 enter_time = bpf_ktime_get_ns();

    u32 index = ENTER_PROG_NO_PAYLOAD_DIRECT;
    if (is_terminating_direct_syscall(sys_id)) {
        index = ENTER_PROG_TERMINATING;
    } else if (is_exec_payload_direct_syscall(sys_id)) {
        index = ENTER_PROG_EXEC;
    } else if (is_path_stat_direct_syscall(sys_id)) {
        index = ENTER_PROG_PATH_STAT;
    } else if (is_path_only_direct_syscall(sys_id)) {
        index = ENTER_PROG_PATH_ONLY;
    } else if (is_dual_path_direct_syscall(sys_id)) {
        index = ENTER_PROG_DUAL_PATH;
    } else if (is_openat2_direct_syscall(sys_id)) {
        index = ENTER_PROG_OPENAT2;
    } else if (is_readlink_direct_syscall(sys_id)) {
        index = ENTER_PROG_READLINK;
    } else if (is_misc_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_MISC_STRUCT;
    } else if (is_small_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_SMALL_STRUCT;
    } else if (is_itimer_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_ITIMER;
    } else if (is_time_struct_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_TIME_STRUCT;
    } else if (is_signal_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_SIGNAL;
    } else if (is_file_time_direct_syscall(sys_id)) {
        index = ENTER_PROG_FILE_TIME;
    } else if (sys_id == SYS_NANOSLEEP || sys_id == SYS_CLOCK_NANOSLEEP) {
        index = ENTER_PROG_SLEEP;
    } else if (sys_id == SYS_FUTEX || sys_id == SYS_FUTEX_WAIT ||
               sys_id == SYS_FUTEX_WAITV || sys_id == SYS_FUTEX_REQUEUE) {
        index = ENTER_PROG_FUTEX;
    } else if (sys_id == SYS_CACHESTAT) {
        index = ENTER_PROG_CACHESTAT;
    } else if (is_capability_direct_syscall(sys_id)) {
        index = ENTER_PROG_CAPABILITY;
    } else if (is_memfd_create_direct_syscall(sys_id)) {
        index = ENTER_PROG_MEMFD;
    } else if (is_prctl_direct_syscall(sys_id)) {
        index = ENTER_PROG_PRCTL;
    } else if (is_clone3_direct_syscall(sys_id)) {
        index = ENTER_PROG_CLONE3;
    } else if (is_bpf_direct_syscall(sys_id)) {
        index = ENTER_PROG_BPF;
    } else if (is_iovec_direct_syscall(sys_id)) {
        index = ENTER_PROG_IOVEC;
    } else if (is_msg_direct_syscall(sys_id)) {
        index = is_single_msg_direct_syscall(sys_id) ? ENTER_PROG_MSG : ENTER_PROG_MMSG;
    } else if (is_fcntl_direct_syscall(sys_id)) {
        index = ENTER_PROG_FCNTL;
    } else if (is_ioctl_direct_syscall(sys_id)) {
        index = ENTER_PROG_IOCTL;
    } else if (is_network_direct_syscall(sys_id)) {
        index = ENTER_PROG_NETWORK;
    } else if (is_key_direct_syscall(sys_id)) {
        index = ENTER_PROG_KEY;
    } else if (is_xattr_direct_syscall(sys_id)) {
        index = ENTER_PROG_XATTR;
    } else if (is_fs_enter_direct_syscall(sys_id)) {
        index = ENTER_PROG_FS;
    } else if (is_aio_direct_syscall(sys_id)) {
        index = ENTER_PROG_AIO;
    } else if (is_poll_direct_syscall(sys_id)) {
        index = ENTER_PROG_POLL;
    } else if (is_select_direct_syscall(sys_id)) {
        index = ENTER_PROG_SELECT;
    } else if (is_epoll_ctl_direct_syscall(sys_id) || is_epoll_pwait2_direct_syscall(sys_id)) {
        index = ENTER_PROG_EPOLL;
    } else if (is_scalar_direct_syscall(sys_id) || is_exit_payload_direct_syscall(sys_id) ||
               is_fd_array_direct_syscall(sys_id) || is_getcwd_direct_syscall(sys_id) ||
               is_time_struct_direct_syscall(sys_id) || is_stat_struct_direct_syscall(sys_id) ||
               is_waitid_direct_syscall(sys_id) ||
               is_misc_struct_direct_syscall(sys_id) || is_small_struct_direct_syscall(sys_id)) {
        index = ENTER_PROG_NO_PAYLOAD_DIRECT;
    } else if (is_payload_direct_syscall(sys_id)) {
        index = ENTER_PROG_PAYLOAD_DIRECT;
    }

    bpf_tail_call(ctx, &enter_progs, index);

    // tail call fallback: keep the syscall observable even if a handler slot is missing.
    s32 stack_id = -1;
    if (cfg && (*cfg & CONFIG_CAPTURE_STACK)) {
        stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    emit_no_payload_enter_event_v2_direct(pid, tid, sys_id, ctx, cfg, enter_time);
    save_pending_syscall_args(tid, pid, sys_id, ctx, enter_time, stack_id);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id == SYS_RT_SIGRETURN || ctx->id == SYS_RT_SIGRETURN_COMPAT) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    struct pending_syscall *p = NULL;
    if (ctx->ret == 0) {
        u32 *p_tid = bpf_map_lookup_elem(&pending_exec_map, &pid);
        if (p_tid) {
            p = bpf_map_lookup_elem(&pending_syscalls, p_tid);
        }
    }
    if (!p) {
        p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    }
    if (!p) return 0;

    u32 index = EXIT_PROG_GENERIC;
    if (is_iovec_base_exit_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_IOVEC_BASE;
    } else if (is_single_msg_direct_syscall(p->sys_id)) {
        index = EXIT_PROG_MSG;
    } else if (is_mmsg_direct_syscall(p->sys_id)) {
        index = (p->sys_id == SYS_RECVMMSG) ? EXIT_PROG_RECVMMSG_BASE0 : EXIT_PROG_MMSG_FINAL;
    }
    bpf_tail_call(ctx, &exit_progs, index);

    // tail call fallback: emit a minimal no-payload exit and consume pending.
    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }
    emit_syscall_exit_event_v2_direct(p, ctx->ret, duration, 0);
    bpf_map_delete_elem(&pending_syscalls, &tid);
    return 0;
}


// IMPACT: recvmsg msg_name is copied from a kretprobe fragment so the nested OUT buffer is observed after __sys_recvmsg returns.
SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_name(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmsg_name_exit_fragment_event_v2_direct(p, ret_value, duration);
    return 0;
}

// IMPACT: recvmsg msg_control is copied from a separate kretprobe fragment to keep trace_sys_exit_msg under verifier limits.
SEC("kretprobe/__sys_recvmsg")
int trace_kretprobe_recvmsg_control(struct pt_regs *ctx) {
    s64 ret_value = (s64)BPF_CORE_READ(ctx, ax);
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct pending_syscall *p = bpf_map_lookup_elem(&pending_syscalls, &tid);
    if (!p) return 0;
    if (p->sys_id != SYS_RECVMSG) return 0;

    u64 duration = 0;
    if (p->enter_time > 0) {
        u64 exit_time = bpf_ktime_get_ns();
        if (exit_time > p->enter_time) {
            duration = exit_time - p->enter_time;
        }
    }

    emit_recvmsg_control_exit_fragment_event_v2_direct(p, ret_value, duration);
    return 0;
}


SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 child_pid = ctx->child_pid;
    // IMPACT: ctx->parent_pid is the forking THREAD's tid; os/exec may fork from
    // any runtime thread, so compare against the parent process tgid instead.
    u32 parent_pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    // IMPACT: when strace-go arms the next fork, the tracee's pid filter is
    // installed at fork time so its initial execve (which happens before
    // cmd.Start() returns) is captured like upstream strace does. os/exec may
    // fork several children from the armed parent, so keep the arm on the
    // parent until one of its children execs.
    u32 arm_key = 0;
    u32 *arm_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    if (arm_parent && *arm_parent != 0 && *arm_parent == parent_pid) {
        u32 val = 1;
        bpf_map_update_elem(&filter_map, &child_pid, &val, BPF_ANY);
        bpf_map_update_elem(&pre_exec_map, &child_pid, &val, BPF_ANY);
    }
    
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

    // IMPACT: once any armed child execs, stop arming so post-start forks are
    // governed by follow-forks instead.
    u32 arm_key = 0;
    u32 *arm_parent = bpf_map_lookup_elem(&arm_fork_map, &arm_key);
    u32 *filter_pid = bpf_map_lookup_elem(&filter_map, &pid);
    if (filter_pid) {
        // IMPACT: always lift pre-exec suppression once a traced process execs;
        // the arm may already be cleared by a racing path, so the suppression
        // clear must not depend on it.
        bpf_map_delete_elem(&pre_exec_map, &pid);
        if (arm_parent && *arm_parent != 0) {
            u32 zero = 0;
            bpf_map_update_elem(&arm_fork_map, &arm_key, &zero, BPF_ANY);
        }
    }

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
    // IMPACT: sched_process_exit fires in the exiting task's context; read the
    // pid/tgid directly instead of relying on the tracepoint struct layout.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    if (!is_lifecycle_task_tracked(pid, tid)) return 0;

    clear_lifecycle_task_state(pid, tid);
    int exit_code = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &task->exit_code);
    }
    emit_lifecycle_event(LIFECYCLE_EXIT, pid, tid, exit_code, 0, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_free")
int trace_sched_process_free(struct trace_event_raw_sched_process_template *ctx) {
    // sched_process_free's tracepoint pid is task-scoped; use the current
    // task identity so cleanup remains correct for non-leader threads.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    if (!is_lifecycle_task_tracked(pid, tid)) return 0;

    clear_lifecycle_task_state(pid, tid);
    emit_lifecycle_event(LIFECYCLE_FREE, pid, tid, pid, 0, 0);
    return 0;
}
