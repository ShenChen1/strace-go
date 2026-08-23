#define _GNU_SOURCE

#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ebpf_bpf_fixture.h"

__attribute__((noinline, used)) static void uprobe_multi_target(void)
{
	asm volatile("");
}

static long load_uprobe_program(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	union bpf_attr load_attr = {};
	load_attr.prog_type = BPF_PROG_TYPE_KPROBE;
	load_attr.expected_attach_type = BPF_TRACE_UPROBE_MULTI;
	load_attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	load_attr.insns = (uint64_t)(uintptr_t)instructions;
	load_attr.license = (uint64_t)(uintptr_t)license;
	return bpf_call(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
}

static int uprobe_multi_offset(uint64_t *offset)
{
	Dl_info info = {};
	if (dladdr((void *)&uprobe_multi_target, &info) == 0 || info.dli_fbase == NULL) {
		return 1;
	}
	*offset = (uint64_t)(uintptr_t)&uprobe_multi_target - (uint64_t)(uintptr_t)info.dli_fbase;
	return 0;
}

static long load_query_program(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 1,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	union bpf_attr load_attr = {};
	load_attr.prog_type = BPF_PROG_TYPE_CGROUP_SKB;
	load_attr.expected_attach_type = BPF_CGROUP_INET_INGRESS;
	load_attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	load_attr.insns = (uint64_t)(uintptr_t)instructions;
	load_attr.license = (uint64_t)(uintptr_t)license;
	long prog_fd = bpf_call(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (prog_fd < 0) {
		fprintf(stderr, "bpf fixture: query BPF_PROG_LOAD: %s\n", strerror(errno));
		return -1;
	}
	return prog_fd;
}

static int read_tracepoint_id(uint64_t *id)
{
	const char *paths[] = {
		"/sys/kernel/tracing/events/syscalls/sys_enter_getpid/id",
		"/sys/kernel/debug/tracing/events/syscalls/sys_enter_getpid/id",
	};
	char buffer[32] = {};
	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			continue;
		}
		ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
		(void)close(fd);
		if (n <= 0) {
			continue;
		}
		char *end = NULL;
		unsigned long parsed = strtoul(buffer, &end, 10);
		if (end != buffer && parsed > 0) {
			*id = parsed;
			return 0;
		}
	}
	return 1;
}

static long load_task_fd_query_program(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	union bpf_attr load_attr = {};
	load_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
	load_attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	load_attr.insns = (uint64_t)(uintptr_t)instructions;
	load_attr.license = (uint64_t)(uintptr_t)license;
	return bpf_call(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
}

static int open_tracepoint_perf_event(uint64_t tracepoint_id)
{
	struct perf_event_attr attr = {};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = tracepoint_id;
	attr.disabled = 1;
	attr.exclude_kernel = 0;
	attr.exclude_hv = 1;
	return (int)syscall(
		__NR_perf_event_open,
		&attr,
		0,
		-1,
		-1,
		0);
}

static int query_task_fd(int perf_fd, char *buffer, uint32_t *buffer_len)
{
	union bpf_attr query_attr = {};
	query_attr.task_fd_query.pid = (uint32_t)getpid();
	query_attr.task_fd_query.fd = (uint32_t)perf_fd;
	query_attr.task_fd_query.buf = (uint64_t)(uintptr_t)buffer;
	query_attr.task_fd_query.buf_len = *buffer_len;
	query_attr.task_fd_query.prog_id = 0;
	long ret = bpf_call(BPF_TASK_FD_QUERY, &query_attr, sizeof(query_attr));
	if (ret != 0 || query_attr.task_fd_query.prog_id == 0 ||
		query_attr.task_fd_query.fd_type != BPF_FD_TYPE_TRACEPOINT ||
		query_attr.task_fd_query.buf_len == 0 ||
		query_attr.task_fd_query.buf_len > *buffer_len) {
		return 1;
	}
	*buffer_len = query_attr.task_fd_query.buf_len;
	return 0;
}

int run_task_fd_query(void)
{
	uint64_t tracepoint_id = 0;
	if (read_tracepoint_id(&tracepoint_id) != 0) {
		fprintf(stderr, "bpf fixture: tracepoint id unavailable\n");
		return 1;
	}
	long prog_fd = load_task_fd_query_program();
	if (prog_fd < 0) {
		fprintf(stderr, "bpf fixture: task query BPF_PROG_LOAD: %s\n", strerror(errno));
		return 1;
	}
	int perf_fd = open_tracepoint_perf_event(tracepoint_id);
	if (perf_fd < 0 || ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, (int)prog_fd) != 0 ||
		ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
		fprintf(stderr, "bpf fixture: task query perf setup: %s\n", strerror(errno));
		if (perf_fd >= 0) {
			(void)close(perf_fd);
		}
		(void)close((int)prog_fd);
		return 1;
	}

	char buffer[64] = {};
	uint32_t buffer_len = sizeof(buffer);
	int result = query_task_fd(perf_fd, buffer, &buffer_len);
	if (result == 0 &&
		(strncmp(buffer, "sys_enter_getpid", strlen("sys_enter_getpid")) != 0 ||
			buffer_len < strlen("sys_enter_getpid"))) {
		fprintf(stderr, "bpf fixture: task query output=%s len=%u\n", buffer, buffer_len);
		result = 1;
	}

	union bpf_attr invalid_attr = {};
	invalid_attr.task_fd_query.pid = (uint32_t)getpid();
	invalid_attr.task_fd_query.fd = (uint32_t)perf_fd;
	invalid_attr.task_fd_query.buf = 1;
	invalid_attr.task_fd_query.buf_len = sizeof(buffer);
	if (bpf_call(BPF_TASK_FD_QUERY, &invalid_attr, sizeof(invalid_attr)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_TASK_FD_QUERY unexpectedly succeeded\n");
		result = 1;
	}

	(void)ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
	(void)close(perf_fd);
	(void)close((int)prog_fd);
	return result;
}

static int attach_query_program(int cgroup_fd, long prog_fd)
{
	union bpf_attr attach_attr = {};
	attach_attr.target_fd = (uint32_t)cgroup_fd;
	attach_attr.attach_bpf_fd = (uint32_t)prog_fd;
	attach_attr.attach_type = BPF_CGROUP_INET_INGRESS;
	attach_attr.attach_flags = BPF_F_ALLOW_MULTI;
	if (bpf_call(BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr)) != 0) {
		fprintf(stderr, "bpf fixture: query BPF_PROG_ATTACH: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

static int query_attached_program(int cgroup_fd)
{
	uint32_t prog_ids[4] = {};
	uint32_t prog_attach_flags[4] = {};
	uint32_t link_ids[4] = {};
	uint32_t link_attach_flags[4] = {};
	union bpf_attr query_attr = {};
	query_attr.query.target_fd = (uint32_t)cgroup_fd;
	query_attr.query.attach_type = BPF_CGROUP_INET_INGRESS;
	query_attr.query.prog_ids = (uint64_t)(uintptr_t)prog_ids;
	query_attr.query.prog_cnt = 4;
	query_attr.query.prog_attach_flags = (uint64_t)(uintptr_t)prog_attach_flags;
	query_attr.query.link_ids = (uint64_t)(uintptr_t)link_ids;
	query_attr.query.link_attach_flags = (uint64_t)(uintptr_t)link_attach_flags;
	query_attr.query.revision = 0;
	long query_ret = bpf_call(BPF_PROG_QUERY, &query_attr, sizeof(query_attr));
	int query_errno = errno;
	if (query_ret != 0 ||
		query_attr.query.prog_cnt == 0 || prog_ids[0] == 0 ||
		prog_attach_flags[0] != BPF_F_ALLOW_MULTI) {
		fprintf(stderr, "bpf fixture: BPF_PROG_QUERY ret=%ld errno=%d count=%u id=%u flags=%u: %s\n",
			query_ret,
			query_errno,
			query_attr.query.prog_cnt,
			prog_ids[0],
			prog_attach_flags[0],
			strerror(query_errno));
		return 1;
	}
	return 0;
}

static int detach_query_program(int cgroup_fd, long prog_fd)
{
	union bpf_attr detach_attr = {};
	detach_attr.target_fd = (uint32_t)cgroup_fd;
	detach_attr.attach_bpf_fd = (uint32_t)prog_fd;
	detach_attr.attach_type = BPF_CGROUP_INET_INGRESS;
	if (bpf_call(BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr)) != 0) {
		fprintf(stderr, "bpf fixture: query BPF_PROG_DETACH: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

int run_prog_query(void)
{
	int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		fprintf(stderr, "bpf fixture: open cgroup: %s\n", strerror(errno));
		return 1;
	}
	long prog_fd = load_query_program();
	if (prog_fd < 0) {
		(void)close(cgroup_fd);
		return 1;
	}
	int attached = 0;
	if (attach_query_program(cgroup_fd, prog_fd) != 0) {
		goto cleanup;
	}
	attached = 1;
	if (query_attached_program(cgroup_fd) != 0 ||
		detach_query_program(cgroup_fd, prog_fd) != 0) {
		goto cleanup;
	}
	attached = 0;

	(void)close((int)prog_fd);
	(void)close(cgroup_fd);
	return 0;

cleanup:
	if (attached) {
		(void)detach_query_program(cgroup_fd, prog_fd);
	}
	if (prog_fd >= 0) {
		(void)close((int)prog_fd);
	}
	(void)close(cgroup_fd);
	return 1;
}

int run_uprobe_multi(const char *binary_path)
{
	uint64_t offset = 0;
	uint64_t cookies[1] = {0xfeedface12345678ULL};
	if (binary_path == NULL || uprobe_multi_offset(&offset) != 0) {
		fprintf(stderr, "bpf fixture: uprobe offset lookup failed\n");
		return 1;
	}

	long prog_fd = load_uprobe_program();
	if (prog_fd < 0) {
		fprintf(stderr, "bpf fixture: uprobe BPF_PROG_LOAD: %s\n", strerror(errno));
		return 1;
	}

	union bpf_attr link_attr = {};
	link_attr.link_create.prog_fd = (uint32_t)prog_fd;
	link_attr.link_create.target_fd = 0;
	link_attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	link_attr.link_create.uprobe_multi.path = (uint64_t)(uintptr_t)binary_path;
	link_attr.link_create.uprobe_multi.offsets = (uint64_t)(uintptr_t)&offset;
	link_attr.link_create.uprobe_multi.cookies = (uint64_t)(uintptr_t)cookies;
	link_attr.link_create.uprobe_multi.cnt = 1;
	link_attr.link_create.uprobe_multi.pid = (uint32_t)getpid();
	long link_fd = bpf_call(BPF_LINK_CREATE, &link_attr, sizeof(link_attr));
	if (link_fd < 0) {
		fprintf(stderr, "bpf fixture: BPF_TRACE_UPROBE_MULTI: %s\n", strerror(errno));
		(void)close((int)prog_fd);
		return 1;
	}

	uprobe_multi_target();
	(void)close((int)link_fd);

	union bpf_attr invalid_attr = {};
	invalid_attr.link_create.prog_fd = (uint32_t)-1;
	invalid_attr.link_create.target_fd = (uint32_t)-1;
	invalid_attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	if (bpf_call(BPF_LINK_CREATE, &invalid_attr, sizeof(invalid_attr)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_TRACE_UPROBE_MULTI unexpectedly succeeded\n");
		(void)close((int)prog_fd);
		return 1;
	}
	(void)close((int)prog_fd);
	return 0;
}
