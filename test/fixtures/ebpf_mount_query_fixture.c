#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXTURE_SYS_STATMOUNT 457
#define FIXTURE_SYS_LISTMOUNT 458
#define FIXTURE_LSMT_ROOT UINT64_MAX
#define FIXTURE_STATMOUNT_SB_BASIC (1ULL << 0)
#define FIXTURE_STATMOUNT_FS_TYPE (1ULL << 5)
#define FIXTURE_STATMOUNT_BUFFER_SIZE 4096

struct fixture_mnt_id_req {
	uint32_t size;
	uint32_t mnt_ns_fd;
	uint64_t mnt_id;
	uint64_t param;
	uint64_t mnt_ns_id;
};

struct fixture_statmount_prefix {
	uint32_t size;
	uint32_t mnt_opts;
	uint64_t mask;
	uint32_t sb_dev_major;
	uint32_t sb_dev_minor;
	uint64_t sb_magic;
	uint32_t sb_flags;
	uint32_t fs_type;
};

static int list_mount_ids(struct fixture_mnt_id_req *request, uint64_t *mount_ids,
			  size_t mount_id_count)
{
	long count = syscall(FIXTURE_SYS_LISTMOUNT, request, mount_ids,
			     mount_id_count, 0U);
	if (count <= 0) {
		fprintf(stderr, "listmount failed: count=%ld errno=%d\n", count, errno);
		return -1;
	}
	return (int) count;
}

static int query_mount(struct fixture_mnt_id_req *request, unsigned char *buffer,
		       size_t buffer_size)
{
	long rc = syscall(FIXTURE_SYS_STATMOUNT, request, buffer, buffer_size, 0U);
	if (rc != 0) {
		fprintf(stderr, "statmount failed: rc=%ld errno=%d\n", rc, errno);
		return -1;
	}
	struct fixture_statmount_prefix *result = (void *) buffer;
	uint64_t required = FIXTURE_STATMOUNT_SB_BASIC | FIXTURE_STATMOUNT_FS_TYPE;
	if (result->size < 512 || (result->mask & required) != required) {
		fprintf(stderr, "statmount result invalid: size=%u mask=%#llx\n",
			result->size, (unsigned long long) result->mask);
		return -1;
	}
	return 0;
}

int main(void)
{
	struct fixture_mnt_id_req request = {
		.size = sizeof(request),
		.mnt_id = FIXTURE_LSMT_ROOT,
	};
	uint64_t mount_ids[8] = {};
	if (list_mount_ids(&request, mount_ids, 8) < 0) {
		return 80;
	}

	request.mnt_id = mount_ids[0];
	request.param = FIXTURE_STATMOUNT_SB_BASIC | FIXTURE_STATMOUNT_FS_TYPE;
	unsigned char buffer[FIXTURE_STATMOUNT_BUFFER_SIZE];
	memset(buffer, 0, sizeof(buffer));
	if (query_mount(&request, buffer, sizeof(buffer)) < 0) {
		return 81;
	}

	puts("mount-query-fixture-ok");
	return 0;
}
