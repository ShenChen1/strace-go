#include "../../bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("struct_ops/test_1")
int BPF_PROG(struct_ops_test_1, struct bpf_dummy_ops_state *state)
{
	(void)ctx;
	if (!state)
		return -1;
	return state->val;
}

SEC("syscall")
int assoc_syscall(void *ctx)
{
	(void)ctx;
	return 0;
}

SEC(".struct_ops.link")
struct bpf_dummy_ops dummy_1 = {
	.test_1 = (void *)struct_ops_test_1,
};

char LICENSE[] SEC("license") = "GPL";
