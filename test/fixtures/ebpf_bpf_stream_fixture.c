#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
	struct bpf_prog_stream_read_opts read_opts = {
		.sz = sizeof(read_opts),
	};
	int count = bpf_prog_stream_read(
		program_fd,
		BPF_STREAM_STDOUT,
		buffer,
		sizeof(buffer) - 1,
		&read_opts);
	if (count > 0 && (size_t)count < sizeof(buffer)) {
		buffer[count] = '\0';
	}
	if (count <= 0 || (size_t)count >= sizeof(buffer) ||
		strcmp(buffer, "stream-data") != 0) {
		fprintf(stderr, "stream: output mismatch count=%d errno=%d\n", count, errno);
		return -1;
	}
	return 0;
}

static int run_stream_failure_probes(int program_fd)
{
	char buffer[16] = "stream-data";
	struct bpf_prog_stream_read_opts read_opts = {
		.sz = sizeof(read_opts),
	};
	if (bpf_prog_stream_read(-1, BPF_STREAM_STDOUT, buffer, sizeof(buffer), &read_opts) >= 0) {
		fprintf(stderr, "stream: invalid program fd unexpectedly succeeded\n");
		return -1;
	}
	if (bpf_prog_stream_read(program_fd, 0, buffer, sizeof(buffer), &read_opts) >= 0) {
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
	if (program_fd >= 0 && run_stream_program(program_fd) == 0 &&
		run_stream_failure_probes(program_fd) == 0) {
		puts("bpf-stream-fixture-ok");
		result = 0;
	}
	bpf_object__close(object);
	return result;
}
