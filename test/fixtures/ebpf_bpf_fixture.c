#define _GNU_SOURCE

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ebpf_bpf_fixture.h"

static int batch_values_have_markers(const char values[][16], uint32_t count)
{
	int saw_value = 0;
	if (count > 2) {
		return 0;
	}
	for (uint32_t i = 0; i < count; i++) {
		if (memcmp(values[i], "value-one", sizeof("value-one") - 1) == 0) {
			saw_value = 1;
		}
	}
	return saw_value;
}

static int run_terminal_map_batch(uint32_t map_fd)
{
	uint64_t out_batch = 0;
	uint32_t output_keys[2] = {};
	char output_values[2][16] = {};
	union bpf_attr batch_attr = {};
	batch_attr.batch.out_batch = (uint64_t)(uintptr_t)&out_batch;
	batch_attr.batch.keys = (uint64_t)(uintptr_t)output_keys;
	batch_attr.batch.values = (uint64_t)(uintptr_t)output_values;
	batch_attr.batch.count = 2;
	batch_attr.batch.map_fd = map_fd;
	long batch_ret = bpf_call(BPF_MAP_LOOKUP_BATCH, &batch_attr, sizeof(batch_attr));
	int batch_errno = errno;
	if (batch_ret != -1 || batch_errno != ENOENT ||
		batch_attr.batch.count == 0 ||
		!batch_values_have_markers(output_values, batch_attr.batch.count)) {
		fprintf(stderr, "bpf fixture: terminal BPF_MAP_LOOKUP_BATCH ret=%ld errno=%d count=%u: %s\n",
			batch_ret, batch_errno, batch_attr.batch.count, strerror(batch_errno));
		return 1;
	}
	return 0;
}

static int run_map_batch_ops(uint32_t map_fd)
{
	uint32_t keys[3] = {0, 1, 2};
	char values[3][16] = {"value-one", "value-one", "value-one"};
	for (size_t i = 0; i < 3; i++) {
		union bpf_attr update_attr = {};
		update_attr.map_fd = map_fd;
		update_attr.key = (uint64_t)(uintptr_t)&keys[i];
		update_attr.value = (uint64_t)(uintptr_t)values[i];
		update_attr.flags = BPF_ANY;
		if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
			fprintf(stderr, "bpf fixture: batch map update: %s\n", strerror(errno));
			return 1;
		}
	}

	for (size_t i = 0; i < 2; i++) {
		char lookup_value[16] = {};
		union bpf_attr lookup_attr = {};
		lookup_attr.map_fd = map_fd;
		lookup_attr.key = (uint64_t)(uintptr_t)&keys[i];
		lookup_attr.value = (uint64_t)(uintptr_t)lookup_value;
		if (bpf_call(BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)) != 0 ||
			memcmp(lookup_value, values[i], sizeof(values[i])) != 0) {
			fprintf(stderr, "bpf fixture: batch element %zu is missing: %s\n",
				i, strerror(errno));
			return 1;
		}
	}

	uint64_t out_batch = 0;
	uint32_t output_keys[2] = {};
	char output_values[2][16] = {};
	union bpf_attr batch_attr = {};
	batch_attr.batch.out_batch = (uint64_t)(uintptr_t)&out_batch;
	batch_attr.batch.keys = (uint64_t)(uintptr_t)output_keys;
	batch_attr.batch.values = (uint64_t)(uintptr_t)output_values;
	batch_attr.batch.count = 2;
	batch_attr.batch.map_fd = map_fd;
	long batch_ret = bpf_call(BPF_MAP_LOOKUP_BATCH, &batch_attr, sizeof(batch_attr));
	if (batch_ret != 0 ||
		!batch_values_have_markers(output_values, batch_attr.batch.count)) {
		fprintf(stderr, "bpf fixture: BPF_MAP_LOOKUP_BATCH ret=%ld errno=%d count=%u: %s\n",
			batch_ret, errno, batch_attr.batch.count, strerror(errno));
		return 1;
	}

	union bpf_attr invalid_batch = batch_attr;
	invalid_batch.batch.count = 2;
	invalid_batch.batch.values = 1;
	if (bpf_call(BPF_MAP_LOOKUP_BATCH, &invalid_batch, sizeof(invalid_batch)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_LOOKUP_BATCH unexpectedly succeeded\n");
		return 1;
	}

	uint64_t delete_out_batch = 0;
	uint32_t lookup_delete_keys[2] = {};
	char lookup_delete_values[2][16] = {};
	union bpf_attr lookup_delete_batch = batch_attr;
	lookup_delete_batch.batch.out_batch = (uint64_t)(uintptr_t)&delete_out_batch;
	lookup_delete_batch.batch.keys = (uint64_t)(uintptr_t)lookup_delete_keys;
	lookup_delete_batch.batch.values = (uint64_t)(uintptr_t)lookup_delete_values;
	lookup_delete_batch.batch.count = 2;
	long lookup_delete_ret = bpf_call(BPF_MAP_LOOKUP_AND_DELETE_BATCH, &lookup_delete_batch, sizeof(lookup_delete_batch));
	if (lookup_delete_ret != 0 ||
		!batch_values_have_markers(lookup_delete_values, lookup_delete_batch.batch.count)) {
		fprintf(stderr, "bpf fixture: BPF_MAP_LOOKUP_AND_DELETE_BATCH ret=%ld errno=%d count=%u: %s\n",
			lookup_delete_ret, errno, lookup_delete_batch.batch.count, strerror(errno));
		return 1;
	}
	if (run_terminal_map_batch(map_fd) != 0) {
		return 1;
	}

	uint32_t delete_keys[1] = {0};
	char delete_value[16] = "delete-value";
	union bpf_attr restore_delete_attr = {};
	restore_delete_attr.map_fd = map_fd;
	restore_delete_attr.key = (uint64_t)(uintptr_t)&delete_keys[0];
	restore_delete_attr.value = (uint64_t)(uintptr_t)delete_value;
	restore_delete_attr.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &restore_delete_attr, sizeof(restore_delete_attr)) != 0) {
		fprintf(stderr, "bpf fixture: restore delete key: %s\n", strerror(errno));
		return 1;
	}

	union bpf_attr delete_batch = {};
	delete_batch.batch.keys = (uint64_t)(uintptr_t)delete_keys;
	delete_batch.batch.count = 1;
	delete_batch.batch.map_fd = map_fd;
	long delete_ret = bpf_call(BPF_MAP_DELETE_BATCH, &delete_batch, sizeof(delete_batch));
	if (delete_ret != 0 || delete_batch.batch.count != 1) {
		fprintf(stderr, "bpf fixture: BPF_MAP_DELETE_BATCH ret=%ld errno=%d count=%u: %s\n",
			delete_ret, errno, delete_batch.batch.count, strerror(errno));
		return 1;
	}
	union bpf_attr invalid_delete_batch = delete_batch;
	invalid_delete_batch.batch.keys = 1;
	if (bpf_call(BPF_MAP_DELETE_BATCH, &invalid_delete_batch, sizeof(invalid_delete_batch)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_DELETE_BATCH unexpectedly succeeded\n");
		return 1;
	}
	return 0;
}

static int run_map_get_next_id(void)
{
	union bpf_attr attr = {};
	attr.start_id = 0;
	attr.next_id = 0xdeadbeefU;
	long ret = bpf_call(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
	if (ret != 0 || attr.next_id == 0 || attr.next_id == 0xdeadbeefU) {
		fprintf(stderr, "bpf fixture: BPF_MAP_GET_NEXT_ID ret=%ld next_id=%u: %s\n",
			ret, attr.next_id, strerror(errno));
		return 1;
	}
	return 0;
}

static int run_hash_cursor_batch(void)
{
	union bpf_attr create_attr = {};
	create_attr.map_type = BPF_MAP_TYPE_HASH;
	create_attr.key_size = 1;
	create_attr.value_size = 16;
	create_attr.max_entries = 2;
	memcpy(create_attr.map_name, "strace_cursor", sizeof("strace_cursor"));
	long map_fd = bpf_call(BPF_MAP_CREATE, &create_attr, sizeof(create_attr));
	if (map_fd < 0) {
		fprintf(stderr, "bpf fixture: cursor BPF_MAP_CREATE: %s\n", strerror(errno));
		return 1;
	}

	unsigned char key = 0x41;
	char value[16] = "cursor-value";
	union bpf_attr update_attr = {};
	update_attr.map_fd = (uint32_t)map_fd;
	update_attr.key = (uint64_t)(uintptr_t)&key;
	update_attr.value = (uint64_t)(uintptr_t)value;
	update_attr.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
		fprintf(stderr, "bpf fixture: cursor BPF_MAP_UPDATE_ELEM: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}

	unsigned char out_batch[4] = {};
	unsigned char output_key[1] = {};
	char output_value[1][16] = {};
	union bpf_attr batch_attr = {};
	batch_attr.batch.out_batch = (uint64_t)(uintptr_t)out_batch;
	batch_attr.batch.keys = (uint64_t)(uintptr_t)output_key;
	batch_attr.batch.values = (uint64_t)(uintptr_t)output_value;
	batch_attr.batch.count = 1;
	batch_attr.batch.map_fd = (uint32_t)map_fd;
	long batch_ret = bpf_call(BPF_MAP_LOOKUP_BATCH, &batch_attr, sizeof(batch_attr));
	int batch_errno = errno;
	int terminal = batch_ret == -1 && batch_errno == ENOENT;
	if ((!terminal && batch_ret != 0) || batch_attr.batch.count == 0 ||
		output_key[0] != key || memcmp(output_value[0], value, sizeof(value)) != 0) {
		fprintf(stderr, "bpf fixture: cursor batch ret=%ld errno=%d count=%u: %s\n",
			batch_ret, batch_errno, batch_attr.batch.count, strerror(batch_errno));
		(void)close((int)map_fd);
		return 1;
	}
	(void)close((int)map_fd);
	return 0;
}

static int run_update_batch(void)
{
	union bpf_attr create_attr = {};
	create_attr.map_type = BPF_MAP_TYPE_HASH;
	create_attr.key_size = 16;
	create_attr.value_size = 16;
	create_attr.max_entries = 2;
	memcpy(create_attr.map_name, "strace_update", sizeof("strace_update"));
	long map_fd = bpf_call(BPF_MAP_CREATE, &create_attr, sizeof(create_attr));
	if (map_fd < 0) {
		fprintf(stderr, "bpf fixture: update BPF_MAP_CREATE: %s\n", strerror(errno));
		return 1;
	}

	char keys[2][16] = {"update-key!-0", "update-key!-1"};
	char values[2][16] = {"update-value!", "update-value!"};
	union bpf_attr batch_attr = {};
	batch_attr.batch.keys = (uint64_t)(uintptr_t)keys;
	batch_attr.batch.values = (uint64_t)(uintptr_t)values;
	batch_attr.batch.count = 2;
	batch_attr.batch.map_fd = (uint32_t)map_fd;
	batch_attr.batch.elem_flags = BPF_ANY;
	long batch_ret = bpf_call(BPF_MAP_UPDATE_BATCH, &batch_attr, sizeof(batch_attr));
	if (batch_ret != 0 || batch_attr.batch.count != 2) {
		fprintf(stderr, "bpf fixture: BPF_MAP_UPDATE_BATCH ret=%ld errno=%d count=%u: %s\n",
			batch_ret, errno, batch_attr.batch.count, strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}

	char lookup_value[16] = {};
	union bpf_attr lookup_attr = {};
	lookup_attr.map_fd = (uint32_t)map_fd;
	lookup_attr.key = (uint64_t)(uintptr_t)keys[0];
	lookup_attr.value = (uint64_t)(uintptr_t)lookup_value;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)) != 0 ||
		memcmp(lookup_value, values[0], sizeof(values[0])) != 0) {
		fprintf(stderr, "bpf fixture: update batch lookup: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}

	union bpf_attr invalid_batch = batch_attr;
	invalid_batch.batch.keys = 1;
	if (bpf_call(BPF_MAP_UPDATE_BATCH, &invalid_batch, sizeof(invalid_batch)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_UPDATE_BATCH unexpectedly succeeded\n");
		(void)close((int)map_fd);
		return 1;
	}
	(void)close((int)map_fd);
	return 0;
}

static int run_map_create(void)
{
	union bpf_attr attr = {};
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = 16;
	attr.max_entries = 4;
	memcpy(attr.map_name, "strace_go_map", sizeof("strace_go_map"));

	long map_fd = bpf_call(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (map_fd < 0) {
		fprintf(stderr, "bpf fixture: BPF_MAP_CREATE: %s\n", strerror(errno));
		return 1;
	}

	struct bpf_map_info info = {};
	union bpf_attr info_attr = {};
	info_attr.info.bpf_fd = (uint32_t)map_fd;
	info_attr.info.info_len = sizeof(info);
	info_attr.info.info = (uint64_t)(uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr)) != 0) {
		fprintf(stderr, "bpf fixture: BPF_OBJ_GET_INFO_BY_FD: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}

	union bpf_attr invalid_info = {};
	invalid_info.info.bpf_fd = (uint32_t)map_fd;
	invalid_info.info.info_len = sizeof(info);
	invalid_info.info.info = 1;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &invalid_info, sizeof(invalid_info)) == 0) {
		fprintf(stderr, "bpf fixture: invalid info pointer unexpectedly succeeded\n");
		(void)close((int)map_fd);
		return 1;
	}

	if (run_map_elem_ops((uint32_t)map_fd) != 0 ||
		run_map_batch_ops((uint32_t)map_fd) != 0) {
		(void)close((int)map_fd);
		return 1;
	}
	if (run_map_get_next_id() != 0) {
		(void)close((int)map_fd);
		return 1;
	}
	(void)close((int)map_fd);
	if (run_hash_cursor_batch() != 0) {
		return 1;
	}
	if (run_update_batch() != 0) {
		return 1;
	}

	union bpf_attr invalid = {};
	invalid.map_type = 0;
	long invalid_ret = bpf_call(BPF_MAP_CREATE, &invalid, sizeof(invalid));
	if (invalid_ret >= 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_CREATE unexpectedly succeeded\n");
		(void)close((int)invalid_ret);
		return 1;
	}
	return 0;
}

static int run_prog_load(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = 0xff,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	char log_buffer[256] = "bpf-verifier-log";
	uint32_t fd_array[] = {17, 23};
	uint32_t func_info[] = {0, 0x1234, 8, 0x5678};
	uint32_t line_info[] = {
		0, 4, 8, 0x10001,
		16, 20, 24, 0x20002,
	};
	uint32_t core_relos[] = {
		0, 0x1234, 4, 1,
		16, 0x5678, 8, 2,
	};
	union bpf_attr attr = {};
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	attr.insns = (uint64_t)(uintptr_t)instructions;
	attr.func_info_rec_size = 8;
	attr.func_info = (uint64_t)(uintptr_t)func_info;
	attr.func_info_cnt = 2;
	attr.line_info_rec_size = 16;
	attr.line_info = (uint64_t)(uintptr_t)line_info;
	attr.line_info_cnt = 2;
	attr.core_relo_cnt = 2;
	attr.core_relos = (uint64_t)(uintptr_t)core_relos;
	attr.core_relo_rec_size = 16;
	attr.fd_array = (uint64_t)(uintptr_t)fd_array;
	attr.fd_array_cnt = sizeof(fd_array) / sizeof(fd_array[0]);
	attr.license = (uint64_t)(uintptr_t)license;
	attr.log_buf = (uint64_t)(uintptr_t)log_buffer;
	attr.log_size = sizeof(log_buffer);
	attr.log_level = 1;

	long prog_fd = bpf_call(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (prog_fd >= 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_PROG_LOAD unexpectedly succeeded\n");
		(void)close((int)prog_fd);
		return 1;
	}

	attr.func_info = 1;
	attr.fd_array = 1;
	attr.fd_array_cnt = 1;
	attr.line_info = 1;
	attr.core_relos = 1;
	prog_fd = bpf_call(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (prog_fd >= 0) {
		fprintf(stderr, "bpf fixture: invalid nested pointer BPF_PROG_LOAD unexpectedly succeeded\n");
		(void)close((int)prog_fd);
		return 1;
	}
	return 0;
}

static int run_prog_test_run(void)
{
	struct bpf_insn instructions[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 2,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	char license[] = "GPL";
	union bpf_attr load_attr = {};
	load_attr.prog_type = BPF_PROG_TYPE_XDP;
	load_attr.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	load_attr.insns = (uint64_t)(uintptr_t)instructions;
	load_attr.license = (uint64_t)(uintptr_t)license;

	long prog_fd = bpf_call(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (prog_fd < 0) {
		fprintf(stderr, "bpf fixture: valid BPF_PROG_LOAD: %s\n", strerror(errno));
		return 1;
	}

	unsigned char data_in[64] = {1, 2, 3, 4};
	unsigned char data_out[64] = {};
	struct xdp_md ctx_in = {};
	struct xdp_md ctx_out = {};
	union bpf_attr test_attr = {};
	test_attr.test.prog_fd = (uint32_t)prog_fd;
	test_attr.test.data_size_in = sizeof(data_in);
	test_attr.test.data_size_out = sizeof(data_out);
	test_attr.test.data_in = (uint64_t)(uintptr_t)data_in;
	test_attr.test.data_out = (uint64_t)(uintptr_t)data_out;
	ctx_in.data = 0;
	ctx_in.data_end = sizeof(data_in);
	ctx_in.data_meta = 0;
	test_attr.test.ctx_size_in = sizeof(ctx_in);
	test_attr.test.ctx_size_out = sizeof(ctx_out);
	test_attr.test.ctx_in = (uint64_t)(uintptr_t)&ctx_in;
	test_attr.test.ctx_out = (uint64_t)(uintptr_t)&ctx_out;
	test_attr.test.repeat = 1;

	long ret = bpf_call(BPF_PROG_TEST_RUN, &test_attr, sizeof(test_attr));
	if (ret != 0) {
		fprintf(stderr, "bpf fixture: BPF_PROG_TEST_RUN: %s\n", strerror(errno));
		(void)close((int)prog_fd);
		return 1;
	}
	if (test_attr.test.data_size_out == 0 || data_out[0] != data_in[0] ||
		test_attr.test.ctx_size_out == 0) {
		fprintf(stderr, "bpf fixture: BPF_PROG_TEST_RUN output is empty\n");
		(void)close((int)prog_fd);
		return 1;
	}
	union bpf_attr invalid_test_attr = test_attr;
	invalid_test_attr.test.prog_fd = (uint32_t)-1;
	if (bpf_call(BPF_PROG_TEST_RUN, &invalid_test_attr, sizeof(invalid_test_attr)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_PROG_TEST_RUN unexpectedly succeeded\n");
		(void)close((int)prog_fd);
		return 1;
	}
	(void)close((int)prog_fd);
	return 0;
}

static int run_btf_load(void)
{
	char btf_data[] = {'b', 'P', 'f', '\0', 'd', 'a', 'T', 'u', 'm'};
	char log_buffer[256] = "btf-verifier-log";
	union bpf_attr attr = {};
	attr.btf = (uint64_t)(uintptr_t)btf_data;
	attr.btf_size = sizeof(btf_data);
	attr.btf_log_buf = (uint64_t)(uintptr_t)log_buffer;
	attr.btf_log_size = sizeof(log_buffer);
	attr.btf_log_level = 1;

	long btf_fd = bpf_call(BPF_BTF_LOAD, &attr, sizeof(attr));
	if (btf_fd >= 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_BTF_LOAD unexpectedly succeeded\n");
		(void)close((int)btf_fd);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 1 || run_map_create() != 0 || run_btf_load() != 0 ||
		run_large_map_value_ops() != 0 || run_prog_test_run() != 0 ||
		run_prog_load() != 0 || run_prog_query() != 0 ||
		run_task_fd_query() != 0 ||
		run_uprobe_multi(argv[0]) != 0) {
		return 1;
	}
	puts("bpf-fixture-ok");
	return 0;
}
