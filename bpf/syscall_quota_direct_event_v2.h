#ifndef STRACE_GO_SYSCALL_QUOTA_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_QUOTA_DIRECT_EVENT_V2_H

#include "syscall_quota_xfs_direct_event_v2.h"

#define QUOTA_DIRECT_DQBLK_SIZE 72
#define QUOTA_DIRECT_DQINFO_SIZE 24
#define QUOTA_DIRECT_FORMAT_SIZE 4

#define QUOTA_DIRECT_SYNC 0x800001
#define QUOTA_DIRECT_ON 0x800002
#define QUOTA_DIRECT_OFF 0x800003
#define QUOTA_DIRECT_GETFMT 0x800004
#define QUOTA_DIRECT_GETINFO 0x800005
#define QUOTA_DIRECT_SETINFO 0x800006
#define QUOTA_DIRECT_GETQUOTA 0x800007
#define QUOTA_DIRECT_SETQUOTA 0x800008
#define QUOTA_DIRECT_GETNEXTQUOTA 0x800009

static __always_inline int is_quota_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_QUOTACTL || sys_id == SYS_QUOTACTL_FD;
}

static __always_inline u32 quota_direct_command(u64 qcmd)
{
    return (u32)qcmd >> 8;
}

static __always_inline u32 quota_direct_enter_command(
    struct trace_event_raw_sys_enter *ctx,
    u32 sys_id)
{
    volatile u64 arg0 = ctx->args[0];
    volatile u64 arg1 = ctx->args[1];
    return quota_direct_command(sys_id == SYS_QUOTACTL_FD ? arg1 : arg0);
}

static __always_inline u32 quota_direct_pending_command(struct pending_syscall *p)
{
    u64 qcmd = p->args[0];
    if (p->sys_id == SYS_QUOTACTL_FD) {
        qcmd = p->args[1];
    }
    return quota_direct_command(qcmd);
}

static __always_inline int quota_direct_has_exit_payload(u32 command)
{
    return command == QUOTA_DIRECT_GETFMT || command == QUOTA_DIRECT_GETINFO ||
        command == QUOTA_DIRECT_GETQUOTA || command == QUOTA_DIRECT_GETNEXTQUOTA ||
        quota_xfs_exit_struct_size(command) > 0;
}

static __always_inline u32 quota_direct_struct_size(u32 command)
{
    if (command == QUOTA_DIRECT_GETFMT) {
        return QUOTA_DIRECT_FORMAT_SIZE;
    }
    if (command == QUOTA_DIRECT_GETINFO || command == QUOTA_DIRECT_SETINFO) {
        return QUOTA_DIRECT_DQINFO_SIZE;
    }
    return QUOTA_DIRECT_DQBLK_SIZE;
}

#include "syscall_quota_capture_direct_event_v2.h"
#include "syscall_quota_emit_direct_event_v2.h"

#endif
