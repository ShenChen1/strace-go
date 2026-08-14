#define _GNU_SOURCE

#include <sched.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int pipe_fds[2];
static atomic_int read_started;
extern char **environ;

static _Noreturn void exit_process(int code)
{
	(void) syscall(SYS_exit_group, code);
	__builtin_unreachable();
}

static void *run_thread(void *unused)
{
	(void) unused;
	char value = 0;
	atomic_store_explicit(&read_started, 1, memory_order_release);
	if (syscall(SYS_read, pipe_fds[0], &value, sizeof(value)) != 1) {
		exit_process(6);
	}
	for (int i = 0; i < 8; i++) {
		if (syscall(SYS_getpid) <= 0) {
			exit_process(7);
		}
	}

	static const char marker[] = "thread-fixture-ok\n";
	if (syscall(SYS_write, STDOUT_FILENO, marker, sizeof(marker) - 1) < 0) {
		exit_process(8);
	}
	char *const argv[] = {(char *) "true", NULL};
	(void) syscall(SYS_execve, "/bin/true", argv, environ);
	exit_process(9);
}

int main(void)
{
	if (pipe(pipe_fds) != 0) {
		fputs("pipe failed\n", stderr);
		return 1;
	}

	pthread_t thread;
	if (pthread_create(&thread, NULL, run_thread, NULL) != 0) {
		fputs("pthread_create failed\n", stderr);
		return 2;
	}

	while (!atomic_load_explicit(&read_started, memory_order_acquire)) {
		sched_yield();
	}
	struct timespec delay = {.tv_nsec = 50 * 1000 * 1000};
	(void) nanosleep(&delay, NULL);

	if (syscall(SYS_getpid) <= 0) {
		fputs("getpid failed\n", stderr);
		return 3;
	}
	if (syscall(SYS_write, pipe_fds[1], "x", 1) != 1) {
		fputs("write failed\n", stderr);
		return 4;
	}

	for (;;) {
		pause();
	}
}
