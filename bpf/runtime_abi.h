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

#include "syscall_numbers_generated.h"

#define EXEC_SNAPSHOT_MAGIC 0x45584543
#define EXEC_PATH_SNAPSHOT_MAX 512
#define EXEC_SNAPSHOT_OFFSET 4096
#define EXEC_ARG_MAX 48
#define EXEC_ENV_MAX 64
#define EXEC_ARG_DATA_SIZE 42
#define EVENT_VERSION 2
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
    u64 lifecycle_map_update_fail;
};

struct fd_path_scratch {
    char name[256];
    u64 components[8];
    u64 args[6];
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
    __uint(max_entries, 11);
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
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} attach_exited_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} attach_roots_map SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fd_path_scratch);
} fd_path_scratch_map SEC(".maps");

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
