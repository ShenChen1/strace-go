#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_signalfd
#define SYS_signalfd 282
#endif

#ifndef SYS_signalfd4
#define SYS_signalfd4 289
#endif

#ifndef SFD_CLOEXEC
#define SFD_CLOEXEC 02000000
#endif

#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK 00004000
#endif

int main(void)
{
	uint64_t usr2 = 1ULL << 11;
	uint64_t usr2_chld = usr2 | (1ULL << 16);
	int fd = syscall(SYS_signalfd4, -1, &usr2, 8, SFD_CLOEXEC | SFD_NONBLOCK);
	if (fd < 0) {
		perror("signalfd4 create");
		return 1;
	}

	int updated = syscall(SYS_signalfd, fd, &usr2_chld, 8);
	if (updated != fd) {
		perror("signalfd update");
		close(fd);
		return 1;
	}

	long invalid_size = syscall(SYS_signalfd, fd, &usr2_chld, 16);
	if (invalid_size >= 0 || errno != EINVAL) {
		fprintf(stderr, "unexpected signalfd size result: %ld errno=%d\n", invalid_size, errno);
		close(fd);
		return 1;
	}

	long invalid_mask = syscall(SYS_signalfd4, -1, (void *)1, 8, 0);
	if (invalid_mask >= 0 || errno != EFAULT) {
		fprintf(stderr, "unexpected signalfd mask result: %ld errno=%d\n", invalid_mask, errno);
		close(fd);
		return 1;
	}

	printf("signalfd-fixture-ok fd=%d\n", fd);
	close(fd);
	return 0;
}
