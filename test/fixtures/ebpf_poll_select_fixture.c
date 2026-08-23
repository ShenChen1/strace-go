#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int run_poll_workload(int read_fd)
{
	struct pollfd fds = {.fd = read_fd, .events = POLLIN, .revents = 0};
	long result = syscall(SYS_poll, &fds, 1, 0);
	if (result != 1 || !(fds.revents & POLLIN)) {
		return 1;
	}

	fds.revents = 0;
	struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
	uint64_t sigmask = 0;
	result = syscall(SYS_ppoll, &fds, 1, &timeout, &sigmask, sizeof(sigmask));
	if (result != 1 || !(fds.revents & POLLIN)) {
		return 2;
	}

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(read_fd, &readfds);
	struct timeval select_timeout = {.tv_sec = 0, .tv_usec = 0};
	result = syscall(
		SYS_select,
		read_fd + 1,
		&readfds,
		NULL,
		NULL,
		&select_timeout);
	if (result != 1 || !FD_ISSET(read_fd, &readfds)) {
		return 3;
	}

	FD_ZERO(&readfds);
	FD_SET(read_fd, &readfds);
	struct timespec pselect_timeout = {.tv_sec = 0, .tv_nsec = 0};
	uint64_t pselect_sigmask = 1;
	struct {
		const uint64_t *sigmask;
		size_t sigsetsize;
	} pselect_arg = {.sigmask = &pselect_sigmask, .sigsetsize = sizeof(pselect_sigmask)};
	result = syscall(
		SYS_pselect6,
		read_fd + 1,
		&readfds,
		NULL,
		NULL,
		&pselect_timeout,
		&pselect_arg);
	if (result != 1 || !FD_ISSET(read_fd, &readfds)) {
		return 4;
	}
	return 0;
}

static int run_failure_workload(void)
{
	struct pollfd *bad_fds = (struct pollfd *)(uintptr_t)1;
	struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
	uint64_t sigmask = 0;
	long result = syscall(SYS_poll, bad_fds, 1, 0);
	int poll_errno = errno;
	long ppoll_result = syscall(
		SYS_ppoll, bad_fds, 1, &timeout, &sigmask, sizeof(sigmask));
	int ppoll_errno = errno;
	long select_result = syscall(
		SYS_select,
		1,
		(fd_set *)(uintptr_t)1,
		NULL,
		NULL,
		&((struct timeval){.tv_sec = 0, .tv_usec = 0}));
	int select_errno = errno;
	struct timespec pselect_timeout = {.tv_sec = 0, .tv_nsec = 0};
	uint64_t pselect_sigmask = 0;
	struct {
		const uint64_t *sigmask;
		size_t sigsetsize;
	} pselect_arg = {.sigmask = &pselect_sigmask, .sigsetsize = sizeof(pselect_sigmask)};
	long pselect_result = syscall(
		SYS_pselect6,
		1,
		(fd_set *)(uintptr_t)1,
		NULL,
		NULL,
		&pselect_timeout,
		&pselect_arg);
	int pselect_errno = errno;
	return result == -1 && poll_errno == EFAULT &&
		ppoll_result == -1 && ppoll_errno == EFAULT &&
		select_result == -1 && select_errno == EFAULT &&
		pselect_result == -1 && pselect_errno == EFAULT ? 0 : 1;
}

int main(void)
{
	int pipe_fds[2] = {-1, -1};
	if (syscall(SYS_pipe, pipe_fds) != 0) {
		return 1;
	}
	if (syscall(SYS_write, pipe_fds[1], "p", 1) != 1) {
		(void)syscall(SYS_close, pipe_fds[0]);
		(void)syscall(SYS_close, pipe_fds[1]);
		return 2;
	}

	int status = run_poll_workload(pipe_fds[0]);
	if (status == 0) {
		status = run_failure_workload();
	}
	(void)syscall(SYS_close, pipe_fds[0]);
	(void)syscall(SYS_close, pipe_fds[1]);
	if (status == 0) {
		puts("poll-select-fixture-ok");
	}
	return status;
}
