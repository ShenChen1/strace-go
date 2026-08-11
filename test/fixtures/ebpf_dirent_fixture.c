#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXTURE_SYS_GETDENTS 78
#define FIXTURE_SYS_GETDENTS64 217

static int run_dirent_syscall(long syscall_id)
{
	char buffer[512];
	errno = 0;
	long rc = syscall(syscall_id, -1, NULL, 0xdeadbeefU);
	if (rc != -1 || errno != EBADF) {
		fprintf(stderr, "unexpected invalid getdents rc=%ld errno=%d\n", rc, errno);
		return 1;
	}

	int fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		perror("open /proc/self/fd");
		return 2;
	}
	rc = syscall(syscall_id, fd, buffer, sizeof(buffer));
	(void) close(fd);
	if (rc <= 0) {
		fprintf(stderr, "getdents syscall %ld rc=%ld errno=%d\n", syscall_id, rc, errno);
		return 3;
	}
	return 0;
}

int main(void)
{
	if (run_dirent_syscall(FIXTURE_SYS_GETDENTS) != 0) {
		return 10;
	}
	if (run_dirent_syscall(FIXTURE_SYS_GETDENTS64) != 0) {
		return 11;
	}
	puts("dirent-fixture-ok");
	return 0;
}
