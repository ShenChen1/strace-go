#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EPOLL_FIFO_PATH "/tmp/strace-go-ebpf-epoll-fifo"

static int run_epoll_fixture(void)
{
	int read_fd = -1;
	int write_fd = -1;
	int epoll_fd = -1;
	int status = 0;
	struct epoll_event add_event = {0};
	struct epoll_event ready_events[2] = {{0}};

	(void) unlink(EPOLL_FIFO_PATH);
	if (mkfifo(EPOLL_FIFO_PATH, 0600) != 0) {
		return 1;
	}
	read_fd = open(EPOLL_FIFO_PATH, O_RDONLY | O_NONBLOCK);
	write_fd = open(EPOLL_FIFO_PATH, O_WRONLY | O_NONBLOCK);
	epoll_fd = syscall(SYS_epoll_create1, 0);
	if (read_fd < 0 || write_fd < 0 || epoll_fd < 0) {
		status = 2;
		goto cleanup;
	}

	add_event.events = EPOLLIN;
	add_event.data.fd = read_fd;
	if (syscall(SYS_epoll_ctl, epoll_fd, EPOLL_CTL_ADD, read_fd, &add_event) != 0) {
		status = 3;
		goto cleanup;
	}
	if (syscall(SYS_write, write_fd, "x", 1) != 1) {
		status = 4;
		goto cleanup;
	}

	long count = syscall(SYS_epoll_wait, epoll_fd, ready_events, 2, 0);
	if (count != 1 || ready_events[0].data.fd != read_fd) {
		status = 5;
	}

cleanup:
	if (epoll_fd >= 0) {
		(void) close(epoll_fd);
	}
	if (write_fd >= 0) {
		(void) close(write_fd);
	}
	if (read_fd >= 0) {
		(void) close(read_fd);
	}
	(void) unlink(EPOLL_FIFO_PATH);
	return status;
}

int main(void)
{
	int status = run_epoll_fixture();
	if (status == 0) {
		(void) puts("epoll-fixture-ok");
	}
	return status;
}
