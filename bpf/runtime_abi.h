#ifndef STRACE_GO_RUNTIME_ABI_H
#define STRACE_GO_RUNTIME_ABI_H

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
#define SYS_GETDENTS 78
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
#define SYS_SETSOCKOPT 54
#define SYS_GETSOCKOPT 55
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
#define SYS_QUOTACTL 179
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
#define SYS_EPOLL_CREATE 213
#define SYS_UTIMES 235
#define SYS_WAITID 247
#define SYS_INOTIFY_INIT 253
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
#define SYS_TIMERFD_CREATE 283
#define SYS_EVENTFD 284
#define SYS_ACCEPT4 288
#define SYS_EVENTFD2 290
#define SYS_EPOLL_CREATE1 291
#define SYS_INOTIFY_INIT1 294
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
#define SYS_STATX 332
#define SYS_IO_PGETEVENTS 333
#define SYS_OPEN_TREE 428
#define SYS_MOVE_MOUNT 429
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SYS_FSPICK 433
#define SYS_CLONE3 435
#define SYS_CLOSE_RANGE 436
#define SYS_OPENAT2 437
#define SYS_FACCESSAT2 439
#define SYS_PROCESS_MADVISE 440
#define SYS_EPOLL_PWAIT2 441
#define SYS_MOUNT_SETATTR 442
#define SYS_QUOTACTL_FD 443
#define SYS_FUTEX_WAITV 449
#define SYS_CACHESTAT 451
#define SYS_FUTEX_WAIT 455
#define SYS_FUTEX_REQUEUE 456
#define SYS_STATMOUNT 457
#define SYS_LISTMOUNT 458
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
#define EVENT_V2_EXIT_BODY_LEN 80
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
    u64 orphan_exit;
    u64 pending_mismatch;
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
    s32 stack_id;
    u32 reserved;
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

enum mmsg_bytes_prog_index {
    MMSG_BYTES_PROG_BASE0 = 0,
    MMSG_BYTES_PROG_BASE1 = 1,
    MMSG_BYTES_PROG_BASE2 = 2,
    MMSG_BYTES_PROG_BASE3 = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u32);
} mmsg_bytes_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u32);
} exit_progs SEC(".maps");

enum recvmsg_prog_index {
    RECVMSG_PROG_NAME = 0,
    RECVMSG_PROG_CONTROL = 1,
    RECVMSG_PROG_FINAL = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u32);
} recvmsg_progs SEC(".maps");

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

#endif
