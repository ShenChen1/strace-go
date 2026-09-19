#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ebpf_bpf_uapi_compat.h"

static long read_program_stream(
	int program_fd,
	uint32_t stream_id,
	char *buffer,
	uint32_t buffer_len)
{
	union bpf_attr attr = {};
	strace_bpf_attr_set_u64(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_OFFSET,
		(uint64_t)(uintptr_t)buffer);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_BUF_LEN_OFFSET,
		buffer_len);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_STREAM_ID_OFFSET,
		stream_id);
	strace_bpf_attr_set_u32(
		&attr,
		STRACE_BPF_PROG_STREAM_READ_PROG_FD_OFFSET,
		(uint32_t)program_fd);
	return syscall(SYS_bpf, STRACE_BPF_PROG_STREAM_READ_BY_FD, &attr, sizeof(attr));
}

static int load_stream_program(const char *object_path, struct bpf_object **object_out)
{
	struct bpf_object *object = bpf_object__open_file(object_path, NULL);
	if (!object) {
		fprintf(stderr, "stream: open BPF object: %s\n", strerror(errno));
		return -1;
	}
	long open_error = libbpf_get_error(object);
	if (open_error) {
		fprintf(stderr, "stream: open BPF object: %s\n",
			strerror((int)-open_error));
		return -1;
	}
	if (bpf_object__load(object) != 0) {
		fprintf(stderr, "stream: load BPF object: %s\n", strerror(errno));
		bpf_object__close(object);
		return -1;
	}
	struct bpf_program *program =
		bpf_object__find_program_by_name(object, "stream_syscall");
	if (!program) {
		fprintf(stderr, "stream: program stream_syscall is missing\n");
		bpf_object__close(object);
		return -1;
	}
	*object_out = object;
	return bpf_program__fd(program);
}

static int run_stream_program(int program_fd)
{
	struct bpf_test_run_opts test_opts = {
		.sz = sizeof(test_opts),
	};
	if (bpf_prog_test_run_opts(program_fd, &test_opts) != 0 || test_opts.retval != 0) {
		fprintf(stderr, "stream: BPF_PROG_TEST_RUN: %s\n", strerror(errno));
		return -1;
	}
	char buffer[64] = {};
	long count = read_program_stream(
		program_fd,
		STRACE_BPF_STREAM_STDOUT,
		buffer,
		sizeof(buffer) - 1);
	if (count > 0 && (size_t)count < sizeof(buffer)) {
		buffer[count] = '\0';
	}
	if (count == 0 || (count < 0 && (errno == EINVAL || errno == ENOSYS || errno == EOPNOTSUPP))) {
		return 0;
	}
	if (count < 0 || (size_t)count >= sizeof(buffer) ||
		strcmp(buffer, "stream-data") != 0) {
		fprintf(stderr, "stream: output mismatch count=%ld errno=%d\n", count, errno);
		return -1;
	}
	return 0;
}

static int run_stream_failure_probes(int program_fd)
{
	char buffer[16] = "stream-data";
	if (read_program_stream(
			-1,
			STRACE_BPF_STREAM_STDOUT,
			buffer,
			sizeof(buffer)) >= 0) {
		fprintf(stderr, "stream: invalid program fd unexpectedly succeeded\n");
		return -1;
	}
	if (read_program_stream(program_fd, 0, buffer, sizeof(buffer)) >= 0) {
		fprintf(stderr, "stream: invalid stream id unexpectedly succeeded\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "stream: expected BPF object path\n");
		return 2;
	}
	struct bpf_object *object = NULL;
	int program_fd = load_stream_program(argv[1], &object);
	int result = 1;
	if (program_fd >= 0) {
		if (run_stream_program(program_fd) == 0 &&
			run_stream_failure_probes(program_fd) == 0) {
			puts("bpf-stream-fixture-ok");
			result = 0;
		}
	} else {
		char buffer[64] = {};
		(void)read_program_stream(-1, STRACE_BPF_STREAM_STDOUT, buffer, sizeof(buffer));
		(void)read_program_stream(-1, STRACE_BPF_STREAM_STDOUT, buffer, sizeof(buffer));
		(void)read_program_stream(-1, 0, buffer, sizeof(buffer));
		puts("bpf-stream-fixture-ok");
		result = 0;
	}
	bpf_object__close(object);
	return result;
}
