#define _GNU_SOURCE

#include <errno.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long bpf_call(enum bpf_cmd command, union bpf_attr *attr)
{
	return syscall(SYS_bpf, command, attr, sizeof(*attr));
}

static int load_iterator_program(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	int btf_id = libbpf_find_vmlinux_btf_id("task", BPF_TRACE_ITER);
	union bpf_attr attr = {};

	if (btf_id < 0) {
		fprintf(stderr, "iter: find task BTF id: %s\n", strerror(-btf_id));
		return -1;
	}
	attr.prog_type = BPF_PROG_TYPE_TRACING;
	attr.expected_attach_type = BPF_TRACE_ITER;
	attr.attach_btf_id = (uint32_t)btf_id;
	attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	attr.insns = (uint64_t)(uintptr_t)instructions;
	attr.license = (uint64_t)(uintptr_t)license;
	long fd = bpf_call(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		fprintf(stderr, "iter: BPF_PROG_LOAD: %s\n", strerror(errno));
		return -1;
	}
	return (int)fd;
}

static int create_iterator_link(int prog_fd)
{
	union bpf_attr attr = {};

	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_ITER;
	long fd = bpf_call(BPF_LINK_CREATE, &attr);
	if (fd < 0) {
		fprintf(stderr, "iter: BPF_LINK_CREATE: %s\n", strerror(errno));
		return -1;
	}
	return (int)fd;
}

static int create_iterator(int link_fd)
{
	union bpf_attr attr = {};

	attr.iter_create.link_fd = (uint32_t)link_fd;
	long fd = bpf_call(BPF_ITER_CREATE, &attr);
	if (fd < 0) {
		fprintf(stderr, "iter: BPF_ITER_CREATE: %s\n", strerror(errno));
		return -1;
	}
	return (int)fd;
}

static int expect_invalid_iterator(void)
{
	union bpf_attr attr = {};

	attr.iter_create.link_fd = UINT32_MAX;
	long ret = bpf_call(BPF_ITER_CREATE, &attr);
	if (ret >= 0) {
		(void)close((int)ret);
		fprintf(stderr, "iter: invalid BPF_ITER_CREATE unexpectedly succeeded\n");
		return -1;
	}
	return 0;
}

int main(void)
{
	int result = 1;
	int prog_fd = load_iterator_program();
	int link_fd = -1;
	int iter_fd = -1;
	char buffer[128];
	ssize_t total = 0;

	if (prog_fd < 0) {
		return 77;
	}
	link_fd = create_iterator_link(prog_fd);
	if (link_fd < 0) {
		goto cleanup;
	}
	iter_fd = create_iterator(link_fd);
	if (iter_fd < 0) {
		goto cleanup;
	}
	for (;;) {
		ssize_t count = read(iter_fd, buffer, sizeof(buffer));
		if (count < 0) {
			fprintf(stderr, "iter: read: %s\n", strerror(errno));
			goto cleanup;
		}
		if (count == 0) {
			break;
		}
		total += count;
	}
	if (expect_invalid_iterator() != 0) {
		goto cleanup;
	}
	result = 0;

cleanup:
	if (iter_fd >= 0) {
		(void)close(iter_fd);
	}
	if (link_fd >= 0) {
		(void)close(link_fd);
	}
	(void)close(prog_fd);
	if (result == 0) {
		printf("bpf-iter-fixture-ok bytes=%zd\n", total);
	}
	return result;
}
