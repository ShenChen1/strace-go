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

static void *run_thread(void *unused)
{
	(void) unused;
	char value = 0;
	atomic_store_explicit(&read_started, 1, memory_order_release);
	if (syscall(SYS_read, pipe_fds[0], &value, sizeof(value)) != 1) {
		return (void *) 1;
	}
	for (int i = 0; i < 8; i++) {
		if (syscall(SYS_getpid) <= 0) {
			return (void *) 1;
		}
	}
	return NULL;
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

	void *result = NULL;
	if (pthread_join(thread, &result) != 0 || result != NULL) {
		fputs("pthread_join failed\n", stderr);
		return 5;
	}
	(void) close(pipe_fds[0]);
	(void) close(pipe_fds[1]);

	fputs("thread-fixture-ok\n", stdout);
	return 0;
}
