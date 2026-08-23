#include "ebpf_bpf_fixture.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

long bpf_call(uint32_t command, union bpf_attr *attr, size_t size)
{
	return syscall(SYS_bpf, command, attr, size);
}

static int run_map_get_next_key_ops(void)
{
	union bpf_attr create_attr = {};
	create_attr.map_type = BPF_MAP_TYPE_ARRAY;
	create_attr.key_size = sizeof(uint32_t);
	create_attr.value_size = sizeof(uint64_t);
	create_attr.max_entries = 4;
	memcpy(create_attr.map_name, "strace_next", sizeof("strace_next"));
	long map_fd = bpf_call(BPF_MAP_CREATE, &create_attr, sizeof(create_attr));
	if (map_fd < 0) {
		fprintf(stderr, "bpf fixture: next-key BPF_MAP_CREATE: %s\n", strerror(errno));
		return 1;
	}
	uint32_t key = 0;
	uint64_t value = 11;
	union bpf_attr update_attr = {};
	update_attr.map_fd = (uint32_t)map_fd;
	update_attr.key = (uint64_t)(uintptr_t)&key;
	update_attr.value = (uint64_t)(uintptr_t)&value;
	update_attr.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
		fprintf(stderr, "bpf fixture: next-key update zero: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}
	key = 1;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
		fprintf(stderr, "bpf fixture: next-key update one: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}
	uint32_t output_key = 99;
	union bpf_attr next_attr = {};
	next_attr.map_fd = (uint32_t)map_fd;
	next_attr.next_key = (uint64_t)(uintptr_t)&output_key;
	if (bpf_call(BPF_MAP_GET_NEXT_KEY, &next_attr, sizeof(next_attr)) != 0 || output_key != 0) {
		fprintf(stderr, "bpf fixture: next-key NULL input: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}
	uint32_t current_key = 0;
	output_key = 0;
	next_attr.key = (uint64_t)(uintptr_t)&current_key;
	if (bpf_call(BPF_MAP_GET_NEXT_KEY, &next_attr, sizeof(next_attr)) != 0 || output_key != 1) {
		fprintf(stderr, "bpf fixture: BPF_MAP_GET_NEXT_KEY: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}
	union bpf_attr invalid_next = next_attr;
	invalid_next.key = 1;
	if (bpf_call(BPF_MAP_GET_NEXT_KEY, &invalid_next, sizeof(invalid_next)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_GET_NEXT_KEY unexpectedly succeeded\n");
		(void)close((int)map_fd);
		return 1;
	}
	(void)close((int)map_fd);
	return 0;
}

int run_map_elem_ops(uint32_t map_fd)
{
	uint32_t key = 0;
	char value[16] = "map-value";
	union bpf_attr update_attr = {};
	update_attr.map_fd = map_fd;
	update_attr.key = (uint64_t)(uintptr_t)&key;
	update_attr.value = (uint64_t)(uintptr_t)value;
	update_attr.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
		fprintf(stderr, "bpf fixture: BPF_MAP_UPDATE_ELEM: %s\n", strerror(errno));
		return 1;
	}
	union bpf_attr invalid_update = update_attr;
	invalid_update.key = 1;
	invalid_update.value = 1;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &invalid_update, sizeof(invalid_update)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_UPDATE_ELEM unexpectedly succeeded\n");
		return 1;
	}

	char lookup_value[16] = {};
	union bpf_attr lookup_attr = {};
	lookup_attr.map_fd = map_fd;
	lookup_attr.key = (uint64_t)(uintptr_t)&key;
	lookup_attr.value = (uint64_t)(uintptr_t)lookup_value;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)) != 0 ||
		memcmp(lookup_value, value, sizeof(value)) != 0) {
		fprintf(stderr, "bpf fixture: BPF_MAP_LOOKUP_ELEM failed: %s\n", strerror(errno));
		return 1;
	}

	union bpf_attr invalid_lookup = lookup_attr;
	invalid_lookup.value = 1;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &invalid_lookup, sizeof(invalid_lookup)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_LOOKUP_ELEM unexpectedly succeeded\n");
		return 1;
	}
	union bpf_attr invalid_lookup_key = lookup_attr;
	invalid_lookup_key.key = 1;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &invalid_lookup_key, sizeof(invalid_lookup_key)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_LOOKUP_ELEM key unexpectedly succeeded\n");
		return 1;
	}

	char delete_value[16] = {};
	union bpf_attr lookup_delete_attr = lookup_attr;
	lookup_delete_attr.value = (uint64_t)(uintptr_t)delete_value;
	if (bpf_call(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &lookup_delete_attr, sizeof(lookup_delete_attr)) != 0 ||
		memcmp(delete_value, value, sizeof(value)) != 0) {
		fprintf(stderr, "bpf fixture: BPF_MAP_LOOKUP_AND_DELETE_ELEM failed: %s\n", strerror(errno));
		return 1;
	}

	uint32_t delete_elem_key = 7;
	char delete_elem_value[16] = "delete-elem";
	union bpf_attr restore_delete_elem = {};
	restore_delete_elem.map_fd = map_fd;
	restore_delete_elem.key = (uint64_t)(uintptr_t)&delete_elem_key;
	restore_delete_elem.value = (uint64_t)(uintptr_t)delete_elem_value;
	restore_delete_elem.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &restore_delete_elem, sizeof(restore_delete_elem)) != 0) {
		fprintf(stderr, "bpf fixture: restore delete elem key: %s\n", strerror(errno));
		return 1;
	}
	union bpf_attr delete_elem = {};
	delete_elem.map_fd = map_fd;
	delete_elem.key = (uint64_t)(uintptr_t)&delete_elem_key;
	if (bpf_call(BPF_MAP_DELETE_ELEM, &delete_elem, sizeof(delete_elem)) != 0) {
		fprintf(stderr, "bpf fixture: BPF_MAP_DELETE_ELEM: %s\n", strerror(errno));
		return 1;
	}
	union bpf_attr invalid_delete_elem = delete_elem;
	invalid_delete_elem.key = 1;
	if (bpf_call(BPF_MAP_DELETE_ELEM, &invalid_delete_elem, sizeof(invalid_delete_elem)) == 0) {
		fprintf(stderr, "bpf fixture: invalid BPF_MAP_DELETE_ELEM unexpectedly succeeded\n");
		return 1;
	}
	return run_map_get_next_key_ops();
}

int run_large_map_value_ops(void)
{
	union bpf_attr create_attr = {};
	create_attr.map_type = BPF_MAP_TYPE_HASH;
	create_attr.key_size = sizeof(uint32_t);
	create_attr.value_size = 64;
	create_attr.max_entries = 1;
	memcpy(create_attr.map_name, "strace_large", sizeof("strace_large"));
	long map_fd = bpf_call(BPF_MAP_CREATE, &create_attr, sizeof(create_attr));
	if (map_fd < 0) {
		fprintf(stderr, "bpf fixture: large BPF_MAP_CREATE: %s\n", strerror(errno));
		return 1;
	}

	uint32_t key = 0x44;
	unsigned char value[64] = {};
	memcpy(value, "large-map-value", sizeof("large-map-value") - 1);
	union bpf_attr update_attr = {};
	update_attr.map_fd = (uint32_t)map_fd;
	update_attr.key = (uint64_t)(uintptr_t)&key;
	update_attr.value = (uint64_t)(uintptr_t)value;
	update_attr.flags = BPF_ANY;
	if (bpf_call(BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr)) != 0) {
		fprintf(stderr, "bpf fixture: large BPF_MAP_UPDATE_ELEM: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}

	unsigned char output[64] = {};
	union bpf_attr lookup_attr = {};
	lookup_attr.map_fd = (uint32_t)map_fd;
	lookup_attr.key = (uint64_t)(uintptr_t)&key;
	lookup_attr.value = (uint64_t)(uintptr_t)output;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)) != 0 ||
		memcmp(output, value, sizeof(value)) != 0) {
		fprintf(stderr, "bpf fixture: large BPF_MAP_LOOKUP_ELEM: %s\n", strerror(errno));
		(void)close((int)map_fd);
		return 1;
	}
	(void)close((int)map_fd);
	return 0;
}
