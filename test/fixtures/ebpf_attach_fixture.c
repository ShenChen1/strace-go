#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int pipe_fds[2];

static void release_blocked_read(int signal_number)
{
	(void) signal_number;
	const char value = 'x';
	(void) syscall(SYS_write, pipe_fds[1], &value, sizeof(value));
}

int main(void)
{
	if (pipe(pipe_fds) != 0) {
		fputs("pipe failed\n", stderr);
		return 1;
	}

	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = release_blocked_read;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR1, &action, NULL) != 0) {
		fputs("sigaction failed\n", stderr);
		return 2;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	fputs("attach-fixture-ready\n", stdout);

	char value = 0;
	long ret = syscall(SYS_read, pipe_fds[0], &value, sizeof(value));
	if (ret != 1) {
		fprintf(stderr, "read failed: %ld errno=%d\n", ret, errno);
		return 3;
	}

	fputs("attach-fixture-ok\n", stdout);
	(void) close(pipe_fds[0]);
	(void) close(pipe_fds[1]);
	return 0;
}
