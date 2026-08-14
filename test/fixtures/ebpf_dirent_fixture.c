#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXTURE_SYS_GETDENTS 78
#define FIXTURE_SYS_GETDENTS64 217

static int create_fixture_entry(const char *directory)
{
	int directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
	if (directory_fd < 0) {
		perror("open fixture directory");
		return 1;
	}
	int entry_fd = openat(directory_fd, "entry", O_WRONLY | O_CREAT | O_EXCL, 0600);
	(void) close(directory_fd);
	if (entry_fd < 0) {
		perror("create fixture entry");
		return 2;
	}
	(void) close(entry_fd);
	return 0;
}

static void remove_fixture_directory(const char *directory)
{
	int directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
	if (directory_fd >= 0) {
		(void) unlinkat(directory_fd, "entry", 0);
		(void) close(directory_fd);
	}
	(void) rmdir(directory);
}

static int run_dirent_syscall(long syscall_id, const char *directory)
{
	char buffer[512];
	errno = 0;
	long rc = syscall(syscall_id, -1, NULL, 0xdeadbeefU);
	if (rc != -1 || errno != EBADF) {
		fprintf(stderr, "unexpected invalid getdents rc=%ld errno=%d\n", rc, errno);
		return 1;
	}

	int fd = open(directory, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		perror("open fixture directory");
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
	char directory[] = "/tmp/strace-go-ebpf-dirent-XXXXXX";
	if (!mkdtemp(directory)) {
		perror("mkdtemp dirent");
		return 4;
	}
	if (create_fixture_entry(directory) != 0) {
		remove_fixture_directory(directory);
		return 5;
	}

	if (run_dirent_syscall(FIXTURE_SYS_GETDENTS, directory) != 0) {
		remove_fixture_directory(directory);
		return 10;
	}
	if (run_dirent_syscall(FIXTURE_SYS_GETDENTS64, directory) != 0) {
		remove_fixture_directory(directory);
		return 11;
	}
	remove_fixture_directory(directory);
	puts("dirent-fixture-ok");
	return 0;
}
