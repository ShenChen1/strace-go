#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FIXTURE_PATH "/tmp/strace-go-ebpf-cloexec-state"

extern char **environ;

static int read_closed_fd(int fd)
{
	char value = 0;
	long ret = syscall(SYS_read, fd, &value, sizeof(value));
	return ret == -1 && errno == EBADF ? 0 : 1;
}

static int has_inherited_fd(int fd)
{
	long ret = syscall(SYS_fcntl, fd, F_GETFD);
	return ret >= 0 && (ret & FD_CLOEXEC) == 0 ? 0 : 1;
}

static int run_after_exec(char **argv)
{
	if (read_closed_fd((int)strtol(argv[2], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[3], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[4], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[5], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[6], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[7], NULL, 10)) != 0) {
		return 3;
	}
	if (has_inherited_fd((int)strtol(argv[8], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[9], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[10], NULL, 10)) != 0 ||
		has_inherited_fd((int)strtol(argv[11], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[12], NULL, 10)) != 0 ||
		has_inherited_fd((int)strtol(argv[13], NULL, 10)) != 0) {
		return 3;
	}
	(void) syscall(SYS_write, STDOUT_FILENO, "cloexec-child-ebadf\n", 20);
	return 0;
}

static int run_parent(const char *self)
{
	int seed = syscall(SYS_open, FIXTURE_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (seed < 0) {
		return 1;
	}
	(void) syscall(SYS_close, seed);

	int fd = syscall(SYS_open, FIXTURE_PATH, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return 2;
	}
	int dup_fd = syscall(SYS_dup3, fd, 40, O_CLOEXEC);
	if (dup_fd < 0) {
		return 3;
	}
	int setfd_fd = syscall(SYS_open, FIXTURE_PATH, O_RDONLY, 0);
	if (setfd_fd < 0 || syscall(SYS_fcntl, setfd_fd, F_SETFD, FD_CLOEXEC) != 0) {
		return 4;
	}
	int range_fd = syscall(SYS_open, FIXTURE_PATH, O_RDONLY, 0);
	if (range_fd < 0 || syscall(SYS_close_range, range_fd, range_fd, CLOSE_RANGE_CLOEXEC) != 0) {
		return 5;
	}
	int combo_fd = syscall(SYS_open, FIXTURE_PATH, O_RDONLY, 0);
	if (combo_fd < 0 || syscall(SYS_close_range, combo_fd, combo_fd,
		CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0) {
		return 6;
	}
	int eventfd_plain_fd = syscall(SYS_eventfd, 0);
	if (eventfd_plain_fd < 0) {
		return 7;
	}
	int eventfd_fd = syscall(SYS_eventfd2, 0, EFD_CLOEXEC);
	if (eventfd_fd < 0) {
		return 8;
	}
	int epoll_fd = syscall(SYS_epoll_create, 1);
	if (epoll_fd < 0) {
		return 9;
	}
	int epoll_cloexec_fd = syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
	if (epoll_cloexec_fd < 0) {
		return 10;
	}
	int timerfd_fd = syscall(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (timerfd_fd < 0) {
		return 11;
	}
	int inotify_plain_fd = syscall(SYS_inotify_init);
	if (inotify_plain_fd < 0) {
		return 12;
	}
	int inotify_cloexec_fd = syscall(SYS_inotify_init1, IN_CLOEXEC);
	if (inotify_cloexec_fd < 0) {
		return 13;
	}
	int pipe_fds[2] = {-1, -1};
	if (syscall(SYS_pipe2, pipe_fds, O_CLOEXEC) != 0) {
		return 14;
	}
	if (syscall(SYS_close_range, pipe_fds[0], pipe_fds[1], 0) != 0) {
		return 15;
	}
	(void) syscall(SYS_close_range, 100, 99, 0);
	(void) unlink(FIXTURE_PATH);

	char fd_text[12][32];
	(void) snprintf(fd_text[0], sizeof(fd_text[0]), "%d", fd);
	(void) snprintf(fd_text[1], sizeof(fd_text[1]), "%d", dup_fd);
	(void) snprintf(fd_text[2], sizeof(fd_text[2]), "%d", setfd_fd);
	(void) snprintf(fd_text[3], sizeof(fd_text[3]), "%d", range_fd);
	(void) snprintf(fd_text[4], sizeof(fd_text[4]), "%d", combo_fd);
	(void) snprintf(fd_text[5], sizeof(fd_text[5]), "%d", eventfd_fd);
	(void) snprintf(fd_text[6], sizeof(fd_text[6]), "%d", eventfd_plain_fd);
	(void) snprintf(fd_text[7], sizeof(fd_text[7]), "%d", epoll_cloexec_fd);
	(void) snprintf(fd_text[8], sizeof(fd_text[8]), "%d", timerfd_fd);
	(void) snprintf(fd_text[9], sizeof(fd_text[9]), "%d", epoll_fd);
	(void) snprintf(fd_text[10], sizeof(fd_text[10]), "%d", inotify_cloexec_fd);
	(void) snprintf(fd_text[11], sizeof(fd_text[11]), "%d", inotify_plain_fd);
	char *const child_argv[] = {
		(char *)self, (char *)"after-exec", fd_text[0], fd_text[1], fd_text[2],
		fd_text[3], fd_text[4], fd_text[5], fd_text[6], fd_text[7], fd_text[8],
		fd_text[9], fd_text[10], fd_text[11], NULL
	};
	pid_t child = fork();
	if (child == 0) {
		(void) syscall(SYS_execve, self, child_argv, environ);
		_exit(127);
	}
	if (child < 0) {
		(void) syscall(SYS_close, fd);
		return 6;
	}

	int status = 0;
	(void) waitpid(child, &status, 0);
	(void) syscall(SYS_close, fd);
	(void) syscall(SYS_close, dup_fd);
	(void) syscall(SYS_close, setfd_fd);
	(void) syscall(SYS_close, range_fd);
	(void) syscall(SYS_close, combo_fd);
	(void) syscall(SYS_close, eventfd_fd);
	(void) syscall(SYS_close, eventfd_plain_fd);
	(void) syscall(SYS_close, epoll_fd);
	(void) syscall(SYS_close, epoll_cloexec_fd);
	(void) syscall(SYS_close, timerfd_fd);
	(void) syscall(SYS_close, inotify_plain_fd);
	(void) syscall(SYS_close, inotify_cloexec_fd);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 5;
}

int main(int argc, char **argv)
{
	if (argc == 14 && argv[1][0] == 'a') {
		return run_after_exec(argv);
	}
	return run_parent(argv[0]);
}
