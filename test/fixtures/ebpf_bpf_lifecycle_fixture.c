#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long bpf_call(enum bpf_cmd command, union bpf_attr *attr)
{
	return syscall(SYS_bpf, command, attr, sizeof(*attr));
}

static int create_map(uint32_t *map_id)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = 16;
	attr.max_entries = 4;
	memcpy(attr.map_name, "strace_life", sizeof("strace_life"));

	long map_fd = bpf_call(BPF_MAP_CREATE, &attr);
	if (map_fd < 0) {
		fprintf(stderr, "lifecycle: BPF_MAP_CREATE: %s\n", strerror(errno));
		return -1;
	}

	struct bpf_map_info info = {};
	union bpf_attr info_attr = {};
	info_attr.info.bpf_fd = (uint32_t)map_fd;
	info_attr.info.info_len = sizeof(info);
	info_attr.info.info = (uint64_t)(uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &info_attr) != 0 || info.id == 0) {
		fprintf(stderr, "lifecycle: map info: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return -1;
	}
	*map_id = info.id;
	return (int)map_fd;
}

static int load_program(
	uint32_t *prog_id,
	enum bpf_prog_type prog_type,
	enum bpf_attach_type expected_attach_type)
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
	attr.prog_type = prog_type;
	attr.expected_attach_type = expected_attach_type;
	attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	attr.insns = (uint64_t)(uintptr_t)instructions;
	attr.license = (uint64_t)(uintptr_t)license;

	long prog_fd = bpf_call(BPF_PROG_LOAD, &attr);
	if (prog_fd < 0) {
		fprintf(stderr, "lifecycle: BPF_PROG_LOAD: %s\n", strerror(errno));
		return -1;
	}

	struct bpf_prog_info info = {};
	union bpf_attr info_attr = {};
	info_attr.info.bpf_fd = (uint32_t)prog_fd;
	info_attr.info.info_len = sizeof(info);
	info_attr.info.info = (uint64_t)(uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &info_attr) != 0 || info.id == 0) {
		fprintf(stderr, "lifecycle: program info: %s\n", strerror(errno));
		(void)close((int)prog_fd);
		return -1;
	}
	*prog_id = info.id;
	return (int)prog_fd;
}

static int check_map_id_lifecycle(int map_fd, uint32_t map_id)
{
	union bpf_attr attr = {};
	attr.map_id = map_id;
	long fd = bpf_call(BPF_MAP_GET_FD_BY_ID, &attr);
	if (fd < 0) {
		fprintf(stderr, "lifecycle: BPF_MAP_GET_FD_BY_ID: %s\n", strerror(errno));
		return 1;
	}
	(void)close((int)fd);

	attr = (union bpf_attr){};
	attr.map_id = UINT32_MAX;
	if (bpf_call(BPF_MAP_GET_FD_BY_ID, &attr) >= 0) {
		fprintf(stderr, "lifecycle: invalid map id unexpectedly succeeded\n");
		return 1;
	}

	attr = (union bpf_attr){};
	attr.map_fd = (uint32_t)map_fd;
	if (bpf_call(BPF_MAP_FREEZE, &attr) != 0) {
		fprintf(stderr, "lifecycle: BPF_MAP_FREEZE: %s\n", strerror(errno));
		return 1;
	}

	uint32_t key = 7;
	char value[16] = "after-freeze";
	attr = (union bpf_attr){};
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	long update_ret = bpf_call(BPF_MAP_UPDATE_ELEM, &attr);
	if (update_ret == 0 || errno != EPERM) {
		fprintf(stderr, "lifecycle: frozen update ret=%ld errno=%d\n", update_ret, errno);
		return 1;
	}
	return 0;
}

static int check_object_path_lifecycle(int map_fd)
{
	char path[] = "/tmp/strace-go-bpf-no-object";
	union bpf_attr attr = {};
	attr.pathname = (uint64_t)(uintptr_t)path;
	attr.bpf_fd = (uint32_t)map_fd;
	if (bpf_call(BPF_OBJ_PIN, &attr) >= 0) {
		fprintf(stderr, "lifecycle: BPF_OBJ_PIN unexpectedly succeeded\n");
		(void)unlink(path);
		return 1;
	}

	attr = (union bpf_attr){};
	attr.pathname = (uint64_t)(uintptr_t)path;
	if (bpf_call(BPF_OBJ_GET, &attr) >= 0) {
		fprintf(stderr, "lifecycle: BPF_OBJ_GET unexpectedly succeeded\n");
		return 1;
	}
	return 0;
}

static int check_program_id_lifecycle(uint32_t prog_id)
{
	union bpf_attr attr = {};
	attr.prog_id = prog_id;
	long fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &attr);
	if (fd < 0) {
		fprintf(stderr, "lifecycle: BPF_PROG_GET_FD_BY_ID: %s\n", strerror(errno));
		return 1;
	}
	(void)close((int)fd);

	attr = (union bpf_attr){};
	attr.prog_id = UINT32_MAX;
	if (bpf_call(BPF_PROG_GET_FD_BY_ID, &attr) >= 0) {
		fprintf(stderr, "lifecycle: invalid program id unexpectedly succeeded\n");
		return 1;
	}
	return 0;
}

static int check_program_next_id(void)
{
	union bpf_attr attr = {};
	attr.start_id = 0;
	attr.next_id = UINT32_MAX;
	if (bpf_call(BPF_PROG_GET_NEXT_ID, &attr) != 0 ||
		attr.next_id == 0 || attr.next_id == UINT32_MAX) {
		fprintf(stderr, "lifecycle: BPF_PROG_GET_NEXT_ID next_id=%u: %s\n",
			attr.next_id, strerror(errno));
		return 1;
	}
	return 0;
}

static int check_btf_id_lifecycle(void)
{
	union bpf_attr attr = {};
	attr.start_id = 0;
	if (bpf_call(BPF_BTF_GET_NEXT_ID, &attr) != 0 || attr.next_id == 0) {
		fprintf(stderr, "lifecycle: BPF_BTF_GET_NEXT_ID next_id=%u: %s\n",
			attr.next_id, strerror(errno));
		return 1;
	}

	uint32_t btf_id = attr.next_id;
	attr = (union bpf_attr){};
	attr.btf_id = btf_id;
	long fd = bpf_call(BPF_BTF_GET_FD_BY_ID, &attr);
	if (fd < 0) {
		fprintf(stderr, "lifecycle: BPF_BTF_GET_FD_BY_ID: %s\n", strerror(errno));
		return 1;
	}
	(void)close((int)fd);

	attr = (union bpf_attr){};
	attr.btf_id = UINT32_MAX;
	if (bpf_call(BPF_BTF_GET_FD_BY_ID, &attr) >= 0) {
		fprintf(stderr, "lifecycle: invalid BTF id unexpectedly succeeded\n");
		return 1;
	}
	return 0;
}

static int get_link_id(int link_fd, uint32_t *link_id)
{
	struct bpf_link_info info = {};
	union bpf_attr attr = {};
	attr.info.bpf_fd = (uint32_t)link_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uint64_t)(uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr) != 0 || info.id == 0) {
		fprintf(stderr, "lifecycle: link info: %s\n", strerror(errno));
		return 1;
	}
	*link_id = info.id;
	return 0;
}

static int check_link_id_queries(uint32_t link_id)
{
	union bpf_attr attr = {};
	attr.link_id = link_id;
	long fd = bpf_call(BPF_LINK_GET_FD_BY_ID, &attr);
	if (fd < 0) {
		fprintf(stderr, "lifecycle: BPF_LINK_GET_FD_BY_ID: %s\n", strerror(errno));
		return 1;
	}
	(void)close((int)fd);

	attr = (union bpf_attr){};
	attr.link_id = UINT32_MAX;
	if (bpf_call(BPF_LINK_GET_FD_BY_ID, &attr) >= 0) {
		fprintf(stderr, "lifecycle: invalid link id unexpectedly succeeded\n");
		return 1;
	}

	attr = (union bpf_attr){};
	attr.start_id = 0;
	attr.next_id = UINT32_MAX;
	if (bpf_call(BPF_LINK_GET_NEXT_ID, &attr) != 0 || attr.next_id == 0) {
		fprintf(stderr, "lifecycle: BPF_LINK_GET_NEXT_ID next_id=%u: %s\n",
			attr.next_id, strerror(errno));
		return 1;
	}
	return 0;
}

static int check_link_lifecycle(int link_fd, uint32_t link_id, int replacement_fd)
{
	union bpf_attr attr = {};
	if (check_link_id_queries(link_id) != 0) {
		return 1;
	}

	attr = (union bpf_attr){};
	attr.link_update.link_fd = (uint32_t)link_fd;
	attr.link_update.new_prog_fd = (uint32_t)replacement_fd;
	long update_ret = bpf_call(BPF_LINK_UPDATE, &attr);
	if (update_ret >= 0 ||
		(errno != EINVAL && errno != ENOTSUP && errno != EOPNOTSUPP && errno != EPERM)) {
		fprintf(stderr, "lifecycle: BPF_LINK_UPDATE ret=%ld errno=%d\n",
			update_ret, errno);
		return 1;
	}

	attr = (union bpf_attr){};
	attr.link_detach.link_fd = (uint32_t)link_fd;
	long detach_ret = bpf_call(BPF_LINK_DETACH, &attr);
	if (detach_ret >= 0 ||
		(errno != EINVAL && errno != ENOTSUP && errno != EOPNOTSUPP && errno != EPERM)) {
		fprintf(stderr, "lifecycle: BPF_LINK_DETACH ret=%ld errno=%d\n",
			detach_ret, errno);
		return 1;
	}
	return 0;
}

static int check_raw_tracepoint(void)
{
	uint32_t prog_id = 0;
	int prog_fd = load_program(&prog_id, BPF_PROG_TYPE_RAW_TRACEPOINT, 0);
	if (prog_fd < 0) {
		return 1;
	}

	char name[] = "sys_enter";
	union bpf_attr attr = {};
	attr.raw_tracepoint.name = (uint64_t)(uintptr_t)name;
	attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
	long link_fd = bpf_call(BPF_RAW_TRACEPOINT_OPEN, &attr);
	if (link_fd < 0) {
		fprintf(stderr, "lifecycle: BPF_RAW_TRACEPOINT_OPEN: %s\n", strerror(errno));
		(void)close(prog_fd);
		return 1;
	}
	uint32_t link_id = 0;
	uint32_t replacement_id = 0;
	int replacement_fd = load_program(&replacement_id, BPF_PROG_TYPE_RAW_TRACEPOINT, 0);
	if (get_link_id((int)link_fd, &link_id) != 0 ||
		replacement_fd < 0 ||
		check_link_lifecycle((int)link_fd, link_id, replacement_fd) != 0) {
		(void)close(replacement_fd);
		(void)close((int)link_fd);
		(void)close(prog_fd);
		return 1;
	}
	(void)close(replacement_fd);
	(void)close((int)link_fd);

	char invalid_name[] = "strace_go_no_such_tracepoint";
	attr = (union bpf_attr){};
	attr.raw_tracepoint.name = (uint64_t)(uintptr_t)invalid_name;
	attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
	if (bpf_call(BPF_RAW_TRACEPOINT_OPEN, &attr) >= 0) {
		fprintf(stderr, "lifecycle: invalid raw tracepoint unexpectedly succeeded\n");
		(void)close(prog_fd);
		return 1;
	}
	(void)close(prog_fd);
	return 0;
}

static int check_cgroup_link_lifecycle(void)
{
	int result = 1;
	int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int prog_fd = -1;
	int replacement_fd = -1;
	long link_fd = -1;
	uint32_t prog_id = 0;
	uint32_t replacement_id = 0;
	uint32_t link_id = 0;
	union bpf_attr attr = {};
	if (cgroup_fd < 0) {
		fprintf(stderr, "lifecycle: open cgroup: %s\n", strerror(errno));
		return 1;
	}

	prog_fd = load_program(&prog_id, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS);
	if (prog_fd < 0) {
		goto cleanup;
	}
	replacement_fd = load_program(
		&replacement_id, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS);
	if (replacement_fd < 0) {
		goto cleanup;
	}

	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_fd = (uint32_t)cgroup_fd;
	attr.link_create.attach_type = BPF_CGROUP_INET_INGRESS;
	link_fd = bpf_call(BPF_LINK_CREATE, &attr);
	if (link_fd < 0) {
		fprintf(stderr, "lifecycle: BPF_LINK_CREATE: %s\n", strerror(errno));
		goto cleanup;
	}
	if (get_link_id((int)link_fd, &link_id) != 0 ||
		check_link_id_queries(link_id) != 0) {
		goto cleanup;
	}

	attr = (union bpf_attr){};
	attr.link_update.link_fd = (uint32_t)link_fd;
	attr.link_update.new_prog_fd = (uint32_t)replacement_fd;
	if (bpf_call(BPF_LINK_UPDATE, &attr) != 0) {
		fprintf(stderr, "lifecycle: cgroup BPF_LINK_UPDATE: %s\n", strerror(errno));
		goto cleanup;
	}

	attr = (union bpf_attr){};
	attr.link_detach.link_fd = (uint32_t)link_fd;
	if (bpf_call(BPF_LINK_DETACH, &attr) != 0) {
		fprintf(stderr, "lifecycle: cgroup BPF_LINK_DETACH: %s\n", strerror(errno));
		goto cleanup;
	}
	result = 0;

cleanup:
	if (link_fd >= 0) {
		(void)close((int)link_fd);
	}
	if (replacement_fd >= 0) {
		(void)close(replacement_fd);
	}
	if (prog_fd >= 0) {
		(void)close(prog_fd);
	}
	(void)close(cgroup_fd);
	return result;
}

static int check_program_map_binding(int prog_fd, int map_fd)
{
	union bpf_attr attr = {};
	attr.prog_bind_map.prog_fd = (uint32_t)prog_fd;
	attr.prog_bind_map.map_fd = (uint32_t)map_fd;
	if (bpf_call(BPF_PROG_BIND_MAP, &attr) != 0) {
		fprintf(stderr, "lifecycle: BPF_PROG_BIND_MAP: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

static int check_enable_stats(void)
{
	union bpf_attr attr = {};
	attr.enable_stats.type = BPF_STATS_RUN_TIME;
	long fd = bpf_call(BPF_ENABLE_STATS, &attr);
	if (fd >= 0) {
		(void)close((int)fd);
		return 0;
	}
	if (errno == EINVAL || errno == ENOSYS || errno == ENOTSUP || errno == EOPNOTSUPP ||
		errno == EPERM) {
		return 0;
	}
	fprintf(stderr, "lifecycle: BPF_ENABLE_STATS: %s\n", strerror(errno));
	return 1;
}

int main(void)
{
	uint32_t map_id = 0;
	int map_fd = create_map(&map_id);
	if (map_fd < 0 || check_map_id_lifecycle(map_fd, map_id) != 0) {
		return 1;
	}
	if (check_object_path_lifecycle(map_fd) != 0) {
		(void)close(map_fd);
		return 1;
	}

	uint32_t prog_id = 0;
	int prog_fd = load_program(&prog_id, BPF_PROG_TYPE_SOCKET_FILTER, 0);
	if (prog_fd < 0) {
		(void)close(map_fd);
		return 1;
	}
	if (check_program_id_lifecycle(prog_id) != 0 ||
		check_program_next_id() != 0 ||
		check_program_map_binding(prog_fd, map_fd) != 0) {
		(void)close(prog_fd);
		(void)close(map_fd);
		return 1;
	}
	(void)close(prog_fd);
	(void)close(map_fd);
	if (check_btf_id_lifecycle() != 0 || check_raw_tracepoint() != 0 ||
		check_cgroup_link_lifecycle() != 0) {
		return 1;
	}

	if (check_enable_stats() != 0) {
		return 1;
	}
	puts("bpf-lifecycle-fixture-ok");
	return 0;
}
