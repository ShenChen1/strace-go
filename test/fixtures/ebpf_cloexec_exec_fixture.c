#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIXTURE_PATH "/tmp/strace-go-ebpf-cloexec-state"

extern char **environ;

static int read_closed_fd(int fd)
{
	char value = 0;
	long ret = syscall(SYS_read, fd, &value, sizeof(value));
	return ret == -1 && errno == EBADF ? 0 : 1;
}

static int run_after_exec(char **argv)
{
	if (read_closed_fd((int)strtol(argv[2], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[3], NULL, 10)) != 0 ||
		read_closed_fd((int)strtol(argv[4], NULL, 10)) != 0) {
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
	int pipe_fds[2] = {-1, -1};
	if (syscall(SYS_pipe2, pipe_fds, O_CLOEXEC) != 0) {
		return 5;
	}
	(void) unlink(FIXTURE_PATH);

	char fd_text[3][32];
	(void) snprintf(fd_text[0], sizeof(fd_text[0]), "%d", fd);
	(void) snprintf(fd_text[1], sizeof(fd_text[1]), "%d", dup_fd);
	(void) snprintf(fd_text[2], sizeof(fd_text[2]), "%d", setfd_fd);
	char *const child_argv[] = {
		(char *)self, (char *)"after-exec", fd_text[0], fd_text[1], fd_text[2], NULL
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
	(void) syscall(SYS_close, pipe_fds[0]);
	(void) syscall(SYS_close, pipe_fds[1]);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 5;
}

int main(int argc, char **argv)
{
	if (argc == 5 && argv[1][0] == 'a') {
		return run_after_exec(argv);
	}
	return run_parent(argv[0]);
}
