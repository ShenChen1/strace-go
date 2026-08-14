#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "ebpf_semantic_fixture.h"

static int run_semantic_fixture(void)
{
	char buf[32];

	usleep(100000);

	int fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		ssize_t nread = read(fd, buf, sizeof(buf));
		(void) nread;
		struct stat st;
		if (syscall(SYS_fstat, fd, &st) != 0) {
			perror("fstat");
			return 73;
		}
		struct statfs sfs;
		if (syscall(SYS_fstatfs, fd, &sfs) != 0) {
			perror("fstatfs");
			return 74;
		}
		(void) close(fd);
	}

	int fs_status = run_semantic_fs_workloads();
	if (fs_status != 0) {
		return fs_status;
	}

	int missing = open("/tmp/strace-go-ebpf-missing-file", O_RDONLY);
	if (missing >= 0) {
		(void) close(missing);
	}

	ssize_t nwritten = write(STDOUT_FILENO, "ebpf-fixture-write\n", 19);
	(void) nwritten;

	struct timespec ts;
	if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		return 71;
	}

	struct timeval tv;
	struct timezone tz;
	if (syscall(SYS_gettimeofday, &tv, &tz) != 0) {
		perror("gettimeofday");
		return 72;
	}

	return run_semantic_runtime_workloads();
}

static int run_perf_fixture(void)
{
	volatile pid_t sink = 0;

	usleep(100000);
	for (int i = 0; i < 5000; i++) {
		sink = getpid();
	}

	return sink == 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "perf") == 0) {
		return run_perf_fixture();
	}
	return run_semantic_fixture();
}
