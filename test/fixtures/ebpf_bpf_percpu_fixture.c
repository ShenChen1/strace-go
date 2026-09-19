#define _GNU_SOURCE

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * These flags are stable BPF syscall UAPI values, but older linux/bpf.h
 * headers do not declare their enum names. Keep the fixture buildable with
 * those headers without changing the values sent to the kernel.
 */
#ifndef BPF_F_CPU
#define BPF_F_CPU 8U
#endif

#ifndef BPF_F_ALL_CPUS
#define BPF_F_ALL_CPUS 16U
#endif

#define VALUE_SIZE 16
#define BATCH_CAPACITY 4

static long bpf_call(uint32_t command, union bpf_attr *attr, size_t size)
{
	return syscall(SYS_bpf, command, attr, size);
}

static int read_possible_cpu_count(size_t *count)
{
	long value = sysconf(_SC_NPROCESSORS_CONF);
	if (value <= 0 || (uint64_t)value > SIZE_MAX / VALUE_SIZE) {
		return 1;
	}
	*count = (size_t)value;
	return 0;
}

static void fill_percpu_values(char *values, size_t cpu_count, const char *marker)
{
	for (size_t cpu = 0; cpu < cpu_count; cpu++) {
		char *value = values + cpu * VALUE_SIZE;
		memset(value, 0, VALUE_SIZE);
		memcpy(value, marker, strlen(marker));
	}
}

static int update_batch(
	int map_fd,
	uint32_t key,
	char *values,
	uint64_t elem_flags)
{
	union bpf_attr attr = {};
	attr.batch.keys = (uint64_t)(uintptr_t)&key;
	attr.batch.values = (uint64_t)(uintptr_t)values;
	attr.batch.count = 1;
	attr.batch.map_fd = (uint32_t)map_fd;
	attr.batch.elem_flags = elem_flags;
	if (bpf_call(BPF_MAP_UPDATE_BATCH, &attr, sizeof(attr)) != 0 || attr.batch.count != 1) {
		if (errno == EINVAL && (elem_flags & (BPF_F_CPU | BPF_F_ALL_CPUS))) {
			return 2;
		}
		fprintf(stderr, "bpf percpu fixture: update key=%u flags=%#llx: %s\n",
			key, (unsigned long long)elem_flags, strerror(errno));
		return 1;
	}
	return 0;
}

static int lookup_batch(int map_fd, const char *marker, size_t cpu_count)
{
	uint64_t out_batch = 0;
	uint32_t keys[BATCH_CAPACITY] = {};
	char *values = calloc(cpu_count * BATCH_CAPACITY, VALUE_SIZE);
	if (values == NULL) {
		return 1;
	}
	union bpf_attr attr = {};
	attr.batch.out_batch = (uint64_t)(uintptr_t)&out_batch;
	attr.batch.keys = (uint64_t)(uintptr_t)keys;
	attr.batch.values = (uint64_t)(uintptr_t)values;
	attr.batch.count = BATCH_CAPACITY;
	attr.batch.map_fd = (uint32_t)map_fd;
	long ret = bpf_call(BPF_MAP_LOOKUP_BATCH, &attr, sizeof(attr));
	int error = errno;
	int valid_ret = ret == 0 || (ret == -1 && error == ENOENT);
	int valid_value = attr.batch.count > 0;
	for (uint32_t index = 0; valid_value && index < attr.batch.count; index++) {
		char *value = values + index * cpu_count * VALUE_SIZE;
		if (memcmp(value, marker, strlen(marker)) == 0) {
			break;
		}
		if (index + 1 == attr.batch.count) {
			valid_value = 0;
		}
	}
	free(values);
	if (!valid_ret || !valid_value) {
		fprintf(stderr, "bpf percpu fixture: lookup batch ret=%ld errno=%d count=%u: %s\n",
			ret, error, attr.batch.count, strerror(error));
		return 1;
	}
	return 0;
}

static int lookup_cpu_value(int map_fd, uint32_t key, const char *marker)
{
	char value[VALUE_SIZE] = {};
	union bpf_attr attr = {};
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_F_CPU;
	if (bpf_call(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) != 0 ||
		memcmp(value, marker, strlen(marker)) != 0) {
		fprintf(stderr, "bpf percpu fixture: cpu lookup key=%u: %s\n", key, strerror(errno));
		return 1;
	}
	return 0;
}

static int run_percpu_map(void)
{
	size_t cpu_count = 0;
	if (read_possible_cpu_count(&cpu_count) != 0) {
		fprintf(stderr, "bpf percpu fixture: invalid possible CPU count\n");
		return 1;
	}
	union bpf_attr create = {};
	create.map_type = BPF_MAP_TYPE_PERCPU_HASH;
	create.key_size = sizeof(uint32_t);
	create.value_size = VALUE_SIZE;
	create.max_entries = 4;
	memcpy(create.map_name, "strace_percpu", sizeof("strace_percpu"));
	long map_fd = bpf_call(BPF_MAP_CREATE, &create, sizeof(create));
	if (map_fd < 0) {
		fprintf(stderr, "bpf percpu fixture: map create: %s\n", strerror(errno));
		return 1;
	}

	char *all_values = calloc(cpu_count, VALUE_SIZE);
	char one_value[VALUE_SIZE] = {};
	if (all_values == NULL) {
		(void)close((int)map_fd);
		return 1;
	}
	fill_percpu_values(all_values, cpu_count, "percpu-no-flags");
	memcpy(one_value, "percpu-cpu", sizeof("percpu-cpu") - 1);
	if (update_batch((int)map_fd, 1, all_values, BPF_ANY) != 0) {
		goto fail;
	}
	int rc2 = update_batch((int)map_fd, 2, one_value, BPF_F_CPU);
	if (rc2 == 1) {
		goto fail;
	}
	if (rc2 == 2) {
		fill_percpu_values(all_values, cpu_count, "percpu-cpu");
		union bpf_attr update2 = {};
		update2.map_fd = (uint32_t)map_fd;
		uint32_t key2 = 2;
		update2.key = (uint64_t)(uintptr_t)&key2;
		update2.value = (uint64_t)(uintptr_t)all_values;
		if (bpf_call(BPF_MAP_UPDATE_ELEM, &update2, sizeof(update2)) != 0) {
			goto fail;
		}
		fill_percpu_values(all_values, cpu_count, "percpu-no-flags");
	}
	memset(one_value, 0, sizeof(one_value));
	memcpy(one_value, "percpu-all-cpus", sizeof("percpu-all-cpus") - 1);
	int rc3 = update_batch((int)map_fd, 3, one_value, BPF_F_ALL_CPUS);
	if (rc3 == 1) {
		goto fail;
	}
	if (lookup_batch((int)map_fd, "percpu-no-flags", cpu_count) != 0 ||
		lookup_cpu_value((int)map_fd, 2, "percpu-cpu") != 0) {
		goto fail;
	}

	union bpf_attr invalid = {};
	invalid.batch.keys = 1;
	invalid.batch.values = (uint64_t)(uintptr_t)one_value;
	invalid.batch.count = 1;
	invalid.batch.map_fd = (uint32_t)map_fd;
	if (bpf_call(BPF_MAP_UPDATE_BATCH, &invalid, sizeof(invalid)) == 0) {
		fprintf(stderr, "bpf percpu fixture: invalid update unexpectedly succeeded\n");
		goto fail;
	}
	free(all_values);
	(void)close((int)map_fd);
	return 0;

fail:
	free(all_values);
	(void)close((int)map_fd);
	return 1;
}

int main(void)
{
	if (run_percpu_map() != 0) {
		return 1;
	}
	puts("bpf-percpu-fixture-ok");
	return 0;
}
