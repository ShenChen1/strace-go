#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t start_thread;

static void release_thread_handler(int signal_number)
{
	(void) signal_number;
	start_thread = 1;
}

static void *run_thread(void *unused)
{
	(void) unused;
	printf("attach-thread-ready %ld\n", syscall(SYS_gettid));
	fflush(stdout);
	while (!start_thread) {
		/* Keep the pre-attach wait in user space so no syscall crosses setup. */
	}
	for (int i = 0; i < 1000; i++) {
		if (syscall(SYS_getpid) <= 0) {
			return (void *) 1;
		}
	}
	return NULL;
}

int main(void)
{
	struct sigaction action = {0};
	action.sa_handler = release_thread_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGUSR1, &action, NULL) != 0) {
		fputs("sigaction failed\n", stderr);
		return 1;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);

	pthread_t thread;
	if (pthread_create(&thread, NULL, run_thread, NULL) != 0) {
		fputs("pthread_create failed\n", stderr);
		return 2;
	}
	void *result = NULL;
	if (pthread_join(thread, &result) != 0 || result != NULL) {
		fputs("pthread_join failed\n", stderr);
		return 3;
	}
	fputs("attach-thread-fixture-ok\n", stdout);
	return 0;
}
