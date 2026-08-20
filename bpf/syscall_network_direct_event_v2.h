#ifndef STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_NETWORK_DIRECT_EVENT_V2_H

struct network_direct_args {
    u64 args[6];
};

static __always_inline int is_network_accept_like_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ACCEPT || sys_id == SYS_ACCEPT4 ||
        sys_id == SYS_GETSOCKNAME || sys_id == SYS_GETPEERNAME;
}

static __always_inline int is_network_sockopt_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETSOCKOPT || sys_id == SYS_GETSOCKOPT;
}

static __always_inline int is_network_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CONNECT || sys_id == SYS_BIND ||
        sys_id == SYS_SENDTO || sys_id == SYS_RECVFROM ||
        is_network_accept_like_direct_syscall(sys_id) ||
        is_network_sockopt_direct_syscall(sys_id);
}

static __always_inline u32 network_direct_enter_socklen_arg(u32 sys_id)
{
    if (sys_id == SYS_RECVFROM) {
        return 5;
    }
    if (is_network_accept_like_direct_syscall(sys_id)) {
        return 2;
    }
    return 6;
}

static __always_inline u64 network_direct_arg(
    struct network_direct_args *args,
    u32 arg_index)
{
    if (arg_index == 0) {
        return args->args[0];
    }
    if (arg_index == 1) {
        return args->args[1];
    }
    if (arg_index == 2) {
        return args->args[2];
    }
    if (arg_index == 3) {
        return args->args[3];
    }
    if (arg_index == 4) {
        return args->args[4];
    }
    if (arg_index == 5) {
        return args->args[5];
    }
    return 0;
}

static __always_inline u64 network_direct_pending_arg(
    struct pending_syscall *p,
    u32 arg_index)
{
    if (arg_index == 1) {
        return p->args[1];
    }
    if (arg_index == 2) {
        return p->args[2];
    }
    if (arg_index == 3) {
        return p->args[3];
    }
    if (arg_index == 4) {
        return p->args[4];
    }
    if (arg_index == 5) {
        return p->args[5];
    }
    return 0;
}

static __always_inline void save_pending_network_syscall_args(
    u32 tid,
    u32 pid,
    u32 sys_id,
    struct network_direct_args *args,
    u64 enter_time,
    s32 stack_id,
    u32 sockaddr_len)
{
    struct pending_syscall p = {};

    p.enter_time = enter_time;
    p.args[0] = args->args[0];
    p.args[1] = args->args[1];
    p.args[2] = args->args[2];
    p.args[3] = args->args[3];
    p.args[4] = args->args[4];
    p.args[5] = args->args[5];
    p.pid = pid;
    p.sys_id = sys_id;
    p.tid = tid;
    p.stack_id = stack_id;

    if (bpf_map_update_elem(&pending_syscalls, &tid, &p, BPF_ANY) != 0) {
        record_pending_update_fail();
    } else {
        save_pending_syscall_aux(tid, sockaddr_len);
    }
}

#include "syscall_network_capture_direct_event_v2.h"
#include "syscall_network_emit_direct_event_v2.h"

#endif
