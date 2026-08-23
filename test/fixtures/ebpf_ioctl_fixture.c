#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int run_ioctl_fixture(void)
{
	int pipe_fds[2] = {-1, -1};
	const char marker[] = "ioctl-payload-17x";
	int available = -1;
	if (syscall(SYS_pipe, pipe_fds) != 0) {
		return 1;
	}
	long written = syscall(SYS_write, pipe_fds[1], marker, sizeof(marker) - 1);
	long result = syscall(SYS_ioctl, pipe_fds[0], FIONREAD, &available);
	if (written != (long)(sizeof(marker) - 1) || result != 0 ||
		available != (int)(sizeof(marker) - 1)) {
		goto fail;
	}
	int failed_value = 0;
	errno = 0;
	long failed = syscall(SYS_ioctl, -1, FIONREAD, &failed_value);
	if (failed != -1 || errno != EBADF) {
		goto fail;
	}
	(void)syscall(SYS_close, pipe_fds[0]);
	(void)syscall(SYS_close, pipe_fds[1]);
	puts("ioctl-fixture-ok");
	return 0;

fail:
	if (pipe_fds[0] >= 0) {
		(void)syscall(SYS_close, pipe_fds[0]);
	}
	if (pipe_fds[1] >= 0) {
		(void)syscall(SYS_close, pipe_fds[1]);
	}
	return 2;
}

int main(void)
{
	return run_ioctl_fixture();
}
