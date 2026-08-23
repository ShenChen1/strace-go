#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long bpf_call(enum bpf_cmd command, union bpf_attr *attr)
{
	return syscall(SYS_bpf, command, attr, sizeof(*attr));
}

static int load_object(const char *path, struct bpf_object **object_out)
{
	struct bpf_object *object = bpf_object__open_file(path, NULL);
	long open_error;

	if (!object) {
		fprintf(stderr, "struct-ops: open BPF object failed\n");
		return -1;
	}
	open_error = libbpf_get_error(object);
	if (open_error) {
		fprintf(stderr, "struct-ops: open BPF object: %s\n",
			strerror((int)-open_error));
		return -1;
	}
	if (bpf_object__load(object) != 0) {
		fprintf(stderr, "struct-ops: load BPF object failed\n");
		bpf_object__close(object);
		return -1;
	}
	*object_out = object;
	return 0;
}

static int associate_program(struct bpf_object *object)
{
	struct bpf_map *map = bpf_object__find_map_by_name(object, "dummy_1");
	struct bpf_program *program =
		bpf_object__find_program_by_name(object, "assoc_syscall");
	int map_fd;
	int program_fd;
	int result;

	if (!map || !program) {
		fprintf(stderr, "struct-ops: required map or program is missing\n");
		return -1;
	}
	map_fd = bpf_map__fd(map);
	program_fd = bpf_program__fd(program);
	if (map_fd < 0 || program_fd < 0) {
		fprintf(stderr, "struct-ops: required map or program FD is invalid\n");
		return -1;
	}
	{
		union bpf_attr attr = {};
		long call_result;

		attr.prog_assoc_struct_ops.map_fd = (unsigned int)map_fd;
		attr.prog_assoc_struct_ops.prog_fd = (unsigned int)program_fd;
		call_result = bpf_call(BPF_PROG_ASSOC_STRUCT_OPS, &attr);
		if (call_result < 0) {
			fprintf(stderr, "struct-ops: valid association: %s\n",
				strerror(errno));
			return -1;
		}
	}
	result = (int)bpf_call(BPF_PROG_ASSOC_STRUCT_OPS, &(union bpf_attr){
		.prog_assoc_struct_ops.map_fd = (unsigned int)map_fd,
		.prog_assoc_struct_ops.prog_fd = (unsigned int)-1,
	});
	if (result >= 0) {
		fprintf(stderr, "struct-ops: invalid association unexpectedly succeeded\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *object = NULL;
	int result;

	if (argc != 2) {
		fprintf(stderr, "struct-ops: expected BPF object path\n");
		return 2;
	}
	result = load_object(argv[1], &object);
	if (result == 0)
		result = associate_program(object);
	bpf_object__close(object);
	if (result != 0)
		return 1;
	puts("bpf-struct-ops-fixture-ok");
	return 0;
}
