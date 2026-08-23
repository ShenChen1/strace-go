#ifndef STRACE_GO_SYSCALL_BPF_NEXT_ID_EXIT_DIRECT_EVENT_V2_H
#define STRACE_GO_SYSCALL_BPF_NEXT_ID_EXIT_DIRECT_EVENT_V2_H

#define BPF_DIRECT_PROG_GET_NEXT_ID 11
#define BPF_DIRECT_MAP_GET_NEXT_ID 12
#define BPF_DIRECT_BTF_GET_NEXT_ID 23
#define BPF_DIRECT_LINK_GET_NEXT_ID 31
#define BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF 4
#define BPF_DIRECT_GET_NEXT_ID_NEXT_ID_SIZE 4
#define BPF_DIRECT_GET_NEXT_ID_OUTPUT_ARG 140

static __always_inline int is_bpf_get_next_id_command_direct(u64 command)
{
    return command == BPF_DIRECT_PROG_GET_NEXT_ID ||
        command == BPF_DIRECT_MAP_GET_NEXT_ID ||
        command == BPF_DIRECT_BTF_GET_NEXT_ID ||
        command == BPF_DIRECT_LINK_GET_NEXT_ID;
}

static __always_inline int emit_bpf_get_next_id_exit_event_v2_direct(
    struct pending_syscall *p,
    s64 ret_value,
    u64 duration)
{
    if (!is_bpf_direct_syscall(p->sys_id) ||
        !is_bpf_get_next_id_command_direct(p->args[0]) ||
        ret_value != 0 ||
        !p->args[1] ||
        p->args[2] < BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF +
            BPF_DIRECT_GET_NEXT_ID_NEXT_ID_SIZE ||
        p->args[1] > 0xffffffffffffffffULL -
            BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF) {
        return 0;
    }

    struct bpf_exit_bytes_request request = {
        .user_ptr = p->args[1] + BPF_DIRECT_GET_NEXT_ID_NEXT_ID_OFF,
        .user_len = BPF_DIRECT_GET_NEXT_ID_NEXT_ID_SIZE,
        .max_len = BPF_DIRECT_GET_NEXT_ID_NEXT_ID_SIZE,
        .storage_len = BPF_DIRECT_BYTES_BUCKET_512,
        .arg_index = BPF_DIRECT_GET_NEXT_ID_OUTPUT_ARG,
    };
    return emit_bpf_exit_bytes_event_v2_direct(p, ret_value, duration, &request);
}

#endif
