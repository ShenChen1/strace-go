#ifndef STRACE_GO_RUNTIME_ABI_H
#define STRACE_GO_RUNTIME_ABI_H

#include "event_abi_generated.h"
#include "syscall_numbers_generated.h"
#include "capture_manifest_generated.h"

#define EXEC_SNAPSHOT_MAGIC 0x45584543
#define EXEC_PATH_SNAPSHOT_MAX 512
#define EXEC_SNAPSHOT_OFFSET 4096
#define EXEC_ARG_MAX 48
#define EXEC_ENV_MAX 64
#define EXEC_ARG_DATA_SIZE 50
#define LIFECYCLE_SNAPSHOT_MAX 4096
#define FD_PATH_NESTED_SCAN_BYTES 128
#define FD_PATH_NESTED_MAX 4

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

_Static_assert(sizeof(struct exec_arg_snapshot) == 64, "exec arg snapshot size drift");

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
};

struct pending_task_state {
    struct pending_syscall syscall;
    u32 aux0;
    u32 valid;
};

struct bpf_stats {
    u64 ringbuf_reserve_fail;
    u64 ringbuf_copy_fail;
    u64 payload_truncated_events;
    u64 pending_update_fail;
    u64 orphan_exit;
    u64 pending_mismatch;
    u64 lifecycle_map_update_fail;
    u64 lifecycle_fork_seen;
    u64 lifecycle_fork_parent_tracked;
    u64 lifecycle_fork_parent_untracked;
    u64 lifecycle_fork_child_filter_installed;
    u64 lifecycle_fork_child_filter_failed;
    u64 lifecycle_exec_seen;
    u64 lifecycle_exec_untracked;
    u64 lifecycle_exit_seen;
    u64 lifecycle_exit_untracked;
};

struct fd_path_scratch {
    char name[256];
    u64 components[8];
    u64 args[6];
    u8 nested_fdset[FD_PATH_NESTED_SCAN_BYTES];
    s32 nested_fd0;
    s32 nested_fd1;
    s32 nested_fd2;
    s32 nested_fd3;
    u32 nested_fd_count;
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

struct syscall_compact_enter_event_v2 {
    u64 args[6];
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

struct signal_event_v2 {
    u32 signo;
    s32 error;
    s32 code;
    u32 sender_pid;
    u32 sender_uid;
    u32 reserved;
};

_Static_assert(sizeof(struct event_v2_header) == EVENT_V2_HEADER_LEN, "event v2 header size drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, version) == EVENT_V2_HEADER_VERSION_OFFSET, "event v2 version offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, event_type) == EVENT_V2_HEADER_EVENT_TYPE_OFFSET, "event v2 type offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, flags) == EVENT_V2_HEADER_FLAGS_OFFSET, "event v2 flags offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, header_len) == EVENT_V2_HEADER_LEN_OFFSET, "event v2 header length offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, size) == EVENT_V2_HEADER_SIZE_OFFSET, "event v2 size offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, pid) == EVENT_V2_HEADER_PID_OFFSET, "event v2 pid offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, tid) == EVENT_V2_HEADER_TID_OFFSET, "event v2 tid offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, sys_id) == EVENT_V2_HEADER_SYS_ID_OFFSET, "event v2 syscall offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, seq) == EVENT_V2_HEADER_SEQ_OFFSET, "event v2 sequence offset drift");
_Static_assert(__builtin_offsetof(struct event_v2_header, ts_ns) == EVENT_V2_HEADER_TS_NS_OFFSET, "event v2 timestamp offset drift");
_Static_assert(sizeof(struct syscall_enter_event_v2) == EVENT_V2_ENTER_BODY_LEN, "event v2 enter size drift");
_Static_assert(sizeof(struct syscall_compact_enter_event_v2) == EVENT_V2_COMPACT_ENTER_BODY_LEN, "event v2 compact enter size drift");
_Static_assert(sizeof(struct syscall_exit_event_v2) == EVENT_V2_EXIT_BODY_LEN, "event v2 exit size drift");
_Static_assert(sizeof(struct lifecycle_event_v2) == EVENT_V2_LIFECYCLE_BODY_LEN, "event v2 lifecycle size drift");
_Static_assert(sizeof(struct signal_event_v2) == EVENT_V2_SIGNAL_BODY_LEN, "event v2 signal size drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, ret) == EVENT_V2_ENTER_RET_OFFSET, "event v2 enter ret offset drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, probe_ret_enter) == EVENT_V2_ENTER_PROBE_RET_ENTER_OFFSET, "event v2 enter probe offset drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, probe_ret_exit) == EVENT_V2_ENTER_PROBE_RET_EXIT_OFFSET, "event v2 enter exit probe offset drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, args) == EVENT_V2_ENTER_ARGS_OFFSET, "event v2 enter args offset drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, capture_len) == EVENT_V2_ENTER_CAPTURE_LEN_OFFSET, "event v2 enter capture offset drift");
_Static_assert(__builtin_offsetof(struct syscall_enter_event_v2, capture_flags) == EVENT_V2_ENTER_CAPTURE_FLAGS_OFFSET, "event v2 enter capture flags offset drift");
_Static_assert(__builtin_offsetof(struct syscall_compact_enter_event_v2, args) == EVENT_V2_COMPACT_ENTER_ARGS_OFFSET, "event v2 compact enter args offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, ret) == EVENT_V2_EXIT_RET_OFFSET, "event v2 exit ret offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, duration_ns) == EVENT_V2_EXIT_DURATION_OFFSET, "event v2 exit duration offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, args) == EVENT_V2_EXIT_ARGS_OFFSET, "event v2 exit args offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, capture_len) == EVENT_V2_EXIT_CAPTURE_LEN_OFFSET, "event v2 exit capture offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, capture_flags) == EVENT_V2_EXIT_CAPTURE_FLAGS_OFFSET, "event v2 exit capture flags offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, stack_id) == EVENT_V2_EXIT_STACK_ID_OFFSET, "event v2 exit stack offset drift");
_Static_assert(__builtin_offsetof(struct syscall_exit_event_v2, reserved) == EVENT_V2_EXIT_RESERVED_OFFSET, "event v2 exit reserved offset drift");
_Static_assert(__builtin_offsetof(struct lifecycle_event_v2, action) == EVENT_V2_LIFECYCLE_ACTION_OFFSET, "event v2 lifecycle action offset drift");
_Static_assert(__builtin_offsetof(struct lifecycle_event_v2, snapshot_len) == EVENT_V2_LIFECYCLE_SNAPSHOT_LEN_OFFSET, "event v2 lifecycle snapshot offset drift");
_Static_assert(__builtin_offsetof(struct lifecycle_event_v2, args) == EVENT_V2_LIFECYCLE_ARGS_OFFSET, "event v2 lifecycle args offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, signo) == EVENT_V2_SIGNAL_NUMBER_OFFSET, "event v2 signal number offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, error) == EVENT_V2_SIGNAL_ERRNO_OFFSET, "event v2 signal errno offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, code) == EVENT_V2_SIGNAL_CODE_OFFSET, "event v2 signal code offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, sender_pid) == EVENT_V2_SIGNAL_SENDER_PID_OFFSET, "event v2 signal sender pid offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, sender_uid) == EVENT_V2_SIGNAL_SENDER_UID_OFFSET, "event v2 signal sender uid offset drift");
_Static_assert(__builtin_offsetof(struct signal_event_v2, reserved) == EVENT_V2_SIGNAL_RESERVED_OFFSET, "event v2 signal reserved offset drift");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 28);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_ENTER_PROG_ARRAY_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} enter_progs SEC(".maps");

/* Direct syscall-id routing keeps the raw dispatcher independent of family predicates. */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_CAPTURE_ROUTE_MAP_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} enter_routes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_MMSG_BYTES_PROG_ARRAY_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} mmsg_bytes_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_EXIT_PROG_ARRAY_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} exit_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_CAPTURE_ROUTE_MAP_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} exit_routes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, STRACE_GO_RECVMSG_PROG_ARRAY_MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} recvmsg_progs SEC(".maps");

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif
#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1ULL << 0)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __uint(max_entries, 0);
    __type(value, struct pending_task_state);
} pending_task_storage SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u32);
} plain_enter_elide_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} arm_fork_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} config_map SEC(".maps");

/* System topology metadata used only for bounded per-CPU map length calculation. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} runtime_meta_map SEC(".maps");

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
