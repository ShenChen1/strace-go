#ifndef STRACE_GO_SYSCALL_TIME_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_TIME_DIRECT_EVENT_V2_H

#define TIME_DIRECT_TIMESPEC_SIZE 16
#define TIME_DIRECT_TIME_T_SIZE 8
#define TIME_DIRECT_TIMEZONE_SIZE 8
#define TIME_DIRECT_ITIMERVAL_SIZE 32
#define TIME_DIRECT_TIMEX_SIZE 208

static __always_inline int is_clock_time_struct_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CLOCK_GETTIME || sys_id == SYS_CLOCK_GETRES;
}

static __always_inline int is_gettimeofday_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETTIMEOFDAY;
}

static __always_inline int is_time_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_TIME;
}

static __always_inline int is_settimeofday_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETTIMEOFDAY;
}

static __always_inline int is_clock_time_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_CLOCK_SETTIME;
}

static __always_inline int is_time_struct_enter_direct_syscall(u32 sys_id)
{
    return is_clock_time_enter_direct_syscall(sys_id) ||
        is_settimeofday_direct_syscall(sys_id);
}

static __always_inline int is_itimer_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETITIMER || sys_id == SYS_SETITIMER;
}

static __always_inline int is_itimer_enter_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_SETITIMER;
}

static __always_inline int is_itimer_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_GETITIMER || sys_id == SYS_SETITIMER;
}

static __always_inline int is_timex_exit_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_ADJTIMEX || sys_id == SYS_CLOCK_ADJTIME;
}

static __always_inline int is_sleep_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_NANOSLEEP || sys_id == SYS_CLOCK_NANOSLEEP;
}

static __always_inline int is_futex_direct_syscall(u32 sys_id)
{
    return sys_id == SYS_FUTEX || sys_id == SYS_FUTEX_WAIT ||
        sys_id == SYS_FUTEX_WAITV || sys_id == SYS_FUTEX_REQUEUE;
}

static __always_inline int is_time_struct_direct_syscall(u32 sys_id)
{
    return is_clock_time_struct_direct_syscall(sys_id) ||
        is_time_direct_syscall(sys_id) ||
        is_gettimeofday_direct_syscall(sys_id) ||
        is_time_struct_enter_direct_syscall(sys_id) ||
        is_file_time_direct_syscall(sys_id) ||
        is_itimer_direct_syscall(sys_id) ||
        is_timex_exit_direct_syscall(sys_id) ||
        is_sleep_direct_syscall(sys_id);
}

static __always_inline int is_sys_exit_direct_syscall(u32 sys_id)
{
    return is_direct_syscall(sys_id) ||
        is_fd_state_exit_direct_syscall(sys_id) ||
        is_getcwd_direct_syscall(sys_id) ||
        is_time_struct_direct_syscall(sys_id) ||
        is_stat_struct_direct_syscall(sys_id) ||
        is_waitid_direct_syscall(sys_id) ||
        is_signal_direct_syscall(sys_id) ||
        is_readlink_direct_syscall(sys_id) ||
        is_fd_array_direct_syscall(sys_id) ||
        is_misc_struct_direct_syscall(sys_id) ||
        is_small_struct_direct_syscall(sys_id) ||
        is_cachestat_direct_syscall(sys_id) ||
        is_capability_direct_syscall(sys_id) ||
        is_memfd_create_direct_syscall(sys_id) ||
        is_prctl_direct_syscall(sys_id) ||
        is_clone3_direct_syscall(sys_id) ||
        is_bpf_direct_syscall(sys_id) ||
        is_iovec_direct_syscall(sys_id) ||
        is_fcntl_direct_syscall(sys_id) ||
        is_ioctl_direct_syscall(sys_id) ||
        is_network_direct_syscall(sys_id) ||
        is_key_direct_syscall(sys_id) ||
        is_xattr_direct_syscall(sys_id) ||
        is_fs_direct_syscall(sys_id) ||
        is_aio_direct_syscall(sys_id) ||
        is_poll_direct_syscall(sys_id) ||
        is_select_direct_syscall(sys_id) ||
        is_epoll_direct_syscall(sys_id) ||
        is_path_only_direct_syscall(sys_id) ||
        is_dual_path_direct_syscall(sys_id) ||
        is_openat2_direct_syscall(sys_id) ||
        is_futex_direct_syscall(sys_id);
}

static __always_inline u32 capture_time_struct_tlv_direct_from_ptr(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    u16 arg_index,
    u64 user_ptr,
    u32 struct_size,
    u16 tlv_flags)
{
    if (struct_size == 0) {
        return 0;
    }

    if (!user_ptr) {
        return 0;
    }

    u32 copied_len = struct_size;
    s32 probe_ret = 0;
    u32 data_offset = payload_offset + PAYLOAD_TLV_HEADER_SIZE;
    void *payload_data = 0;
    if (struct_size == TIME_DIRECT_TIMEZONE_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMEZONE_SIZE);
    } else if (struct_size == TIME_DIRECT_ITIMERVAL_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_ITIMERVAL_SIZE);
    } else if (struct_size == TIME_DIRECT_TIMEX_SIZE) {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMEX_SIZE);
    } else {
        payload_data = bpf_dynptr_data(ptr, data_offset, TIME_DIRECT_TIMESPEC_SIZE);
    }
    if (!payload_data) {
        record_ringbuf_copy_fail();
        probe_ret = -1;
        copied_len = 0;
    } else {
        long err = bpf_probe_read_user(payload_data, struct_size, (void *)user_ptr);
        if (err < 0) {
            probe_ret = err;
            copied_len = 0;
        }
    }

    if (!payload_tlv_write_header_direct(
            ptr,
            payload_offset,
            PAYLOAD_TLV_KIND_STRUCT,
            arg_index,
            tlv_flags,
            struct_size,
            copied_len,
            probe_ret,
            user_ptr)) {
        return 0;
    }
    return PAYLOAD_TLV_HEADER_SIZE + copied_len;
}

static __always_inline u32 capture_time_struct_tlv_direct(
    struct bpf_dynptr *ptr,
    u32 payload_offset,
    struct pending_syscall *p,
    u16 arg_index,
    u32 struct_size)
{
    if (arg_index >= 6) {
        return 0;
    }
    return capture_time_struct_tlv_direct_from_ptr(
        ptr,
        payload_offset,
        arg_index,
        p->args[arg_index],
        struct_size,
        PAYLOAD_TLV_FLAG_DIRECTION_OUT);
}

#include "syscall_time_emit_direct_event_v2.h"

#endif
