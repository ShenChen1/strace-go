#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ebpf_bpf_uapi_compat.h"

static long bpf_call(uint32_t command, union bpf_attr *attr)
{
	return syscall(SYS_bpf, command, attr, sizeof(*attr));
}

static const char *probe_status(long ret, int error, const char *probe)
{
	if (ret >= 0) {
		return "supported";
	}
	if (error == ENOSYS) {
		return "unsupported";
	}
	if (strcmp(probe, "valid") == 0 &&
		(error == EINVAL || error == EOPNOTSUPP || error == EPERM ||
		 error == EACCES || error == ENODEV || error == ENOENT)) {
		return "environment_blocked";
	}
	if (error == EPERM || error == EACCES) {
		return "environment_blocked";
	}
	return "invalid_input";
}

static void emit_capability_probe(
	uint32_t command,
	const char *name,
	long ret,
	int error,
	const char *probe)
{
	printf(
		"{\"type\":\"bpf_capability\",\"command\":%u,"
		"\"name\":\"%s\",\"status\":\"%s\","
		"\"errno\":%d,\"probe\":\"%s\"}\n",
		command,
		name,
		probe_status(ret, error, probe),
		error,
		probe);
}

static void probe_enable_stats(void)
{
	union bpf_attr attr = {};
	attr.enable_stats.type = BPF_STATS_RUN_TIME;
	long ret = bpf_call(STRACE_BPF_ENABLE_STATS, &attr);
	int error = ret < 0 ? errno : 0;
	if (ret >= 0) {
		(void)close((int)ret);
	}
	emit_capability_probe(STRACE_BPF_ENABLE_STATS, "BPF_ENABLE_STATS", ret, error, "valid");
}

static void probe_token_create(void)
{
	int bpffs_fd = open("/sys/fs/bpf", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (bpffs_fd < 0) {
		emit_capability_probe(STRACE_BPF_TOKEN_CREATE, "BPF_TOKEN_CREATE", -1, errno, "valid");
		return;
	}
	union bpf_attr attr = {};
	long ret = bpf_call(STRACE_BPF_TOKEN_CREATE, &attr);
	int error = ret < 0 ? errno : 0;
	if (ret >= 0) {
		(void)close((int)ret);
	}
	emit_capability_probe(STRACE_BPF_TOKEN_CREATE, "BPF_TOKEN_CREATE", ret, error, "valid");
	(void)close(bpffs_fd);
}

static int create_map(void)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 1;
	memcpy(attr.map_name, "strace_rare", sizeof("strace_rare"));
	long fd = bpf_call(BPF_MAP_CREATE, &attr);
	if (fd < 0) {
		fprintf(stderr, "rare: BPF_MAP_CREATE: %s\n", strerror(errno));
		return -1;
	}
	return (int)fd;
}

static int load_program(void)
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
	union bpf_attr attr = {};
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	attr.insns = (uint64_t)(uintptr_t)instructions;
	attr.license = (uint64_t)(uintptr_t)license;
	long fd = bpf_call(BPF_PROG_LOAD, &attr);
	if (fd < 0) {
		fprintf(stderr, "rare: BPF_PROG_LOAD: %s\n", strerror(errno));
		return -1;
	}
	return (int)fd;
}

static int expect_failure(
	uint32_t command,
	union bpf_attr *attr,
	const char *name,
	int returns_fd,
	const char *probe)
{
	long ret = bpf_call(command, attr);
	int error = ret < 0 ? errno : 0;
	if (ret < 0) {
		emit_capability_probe((uint32_t)command, name, ret, error, probe);
		return 0;
	}
	emit_capability_probe((uint32_t)command, name, ret, error, probe);
	if (returns_fd) {
		(void)close((int)ret);
	}
	fprintf(stderr, "rare: %s unexpectedly succeeded ret=%ld\n", name, ret);
	return 1;
}

static int probe_invalid_iter(int prog_fd)
{
	union bpf_attr attr = {};
	attr.iter_create.link_fd = (uint32_t)prog_fd;
	return expect_failure(
		STRACE_BPF_ITER_CREATE,
		&attr,
		"BPF_ITER_CREATE",
		1,
		"invalid-object");
}

static int probe_invalid_token(void)
{
	union bpf_attr attr = {};
	strace_bpf_attr_set_u32(&attr, STRACE_BPF_TOKEN_CREATE_FLAGS_OFFSET, 0);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_TOKEN_CREATE_BPFFS_FD_OFFSET,
		UINT32_MAX);
	return expect_failure(
		STRACE_BPF_TOKEN_CREATE,
		&attr,
		"BPF_TOKEN_CREATE",
		1,
		"invalid-object");
}

static int probe_invalid_stream(int prog_fd)
{
	char stream_buf[16] = "stream-data";
	union bpf_attr attr = {};
	strace_bpf_attr_set_u64(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_OFFSET,
		(uint64_t)(uintptr_t)stream_buf);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_LEN_OFFSET,
		sizeof(stream_buf) - 1);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_ID_OFFSET,
		0);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_PROG_FD_OFFSET,
		(uint32_t)prog_fd);
	return expect_failure(
		STRACE_BPF_PROG_STREAM_READ_BY_FD,
		&attr,
		"BPF_PROG_STREAM_READ_BY_FD",
		0,
		"invalid-object");
}

static int probe_invalid_assoc(int map_fd, int prog_fd)
{
	union bpf_attr attr = {};
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_ASSOC_STRUCT_OPS_MAP_FD_OFFSET,
		(uint32_t)map_fd);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_ASSOC_STRUCT_OPS_PROG_FD_OFFSET,
		(uint32_t)prog_fd);
	return expect_failure(
		STRACE_BPF_PROG_ASSOC_STRUCT_OPS,
		&attr,
		"BPF_PROG_ASSOC_STRUCT_OPS",
		0,
		"invalid-object");
}

int main(void)
{
	int result = 1;
	probe_enable_stats();
	probe_token_create();
	int map_fd = create_map();
	int prog_fd = -1;
	if (map_fd < 0) {
		return 1;
	}
	prog_fd = load_program();
	if (prog_fd < 0) {
		goto cleanup;
	}

	if (probe_invalid_iter(prog_fd) != 0 ||
		probe_invalid_token() != 0 ||
		probe_invalid_stream(prog_fd) != 0 ||
		probe_invalid_assoc((int)map_fd, prog_fd) != 0) {
		goto cleanup;
	}
	result = 0;

cleanup:
	if (prog_fd >= 0) {
		(void)close(prog_fd);
	}
	(void)close(map_fd);
	if (result == 0) {
		puts("bpf-rare-fixture-ok");
	}
	return result;
}
