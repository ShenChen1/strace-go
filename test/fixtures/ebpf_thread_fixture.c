#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *run_thread(void *unused)
{
	(void) unused;
	for (int i = 0; i < 8; i++) {
		if (syscall(SYS_getpid) <= 0) {
			return (void *) 1;
		}
	}
	return NULL;
}

int main(void)
{
	pthread_t thread;
	if (pthread_create(&thread, NULL, run_thread, NULL) != 0) {
		fputs("pthread_create failed\n", stderr);
		return 1;
	}

	void *result = NULL;
	if (pthread_join(thread, &result) != 0 || result != NULL) {
		fputs("pthread_join failed\n", stderr);
		return 2;
	}

	fputs("thread-fixture-ok\n", stdout);
	return 0;
}
