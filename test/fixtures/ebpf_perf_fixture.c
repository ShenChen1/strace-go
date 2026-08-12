#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int parse_count(const char *text, int fallback)
{
	char *end = NULL;
	long value = strtol(text, &end, 10);
	if (end == text || *end != '\0' || value <= 0 || value > 100000) {
		return fallback;
	}
	return (int) value;
}

static int run_scalar(int iterations)
{
	struct timespec timestamp;
	volatile long last_pid = 0;

	for (int i = 0; i < iterations; i++) {
		last_pid = syscall(SYS_getpid);
		if (last_pid < 0 || syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &timestamp) != 0) {
			return 1;
		}
	}
	return last_pid == 0;
}

static int run_io(int iterations)
{
	char buffer[64];
	int input = open("/dev/zero", O_RDONLY);
	int output = open("/dev/null", O_WRONLY);
	if (input < 0 || output < 0) {
		return 1;
	}
	memcpy(buffer, "ebpf-perf-write", sizeof("ebpf-perf-write") - 1);

	for (int i = 0; i < iterations; i++) {
		long read_count = syscall(SYS_read, input, buffer, sizeof(buffer));
		long write_count = syscall(SYS_write, output, buffer, sizeof(buffer));
		if (read_count != (long) sizeof(buffer) || write_count != (long) sizeof(buffer)) {
			close(input);
			close(output);
			return 2;
		}
	}
	close(input);
	close(output);
	return 0;
}

static int run_lifecycle(int iterations)
{
	for (int i = 0; i < iterations; i++) {
		pid_t child = (pid_t) syscall(SYS_fork);
		if (child == 0) {
			execl("/bin/true", "true", (char *) NULL);
			_exit(127);
		}
		if (child < 0) {
			return 1;
		}
		int status = 0;
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			return 2;
		}
	}
	return 0;
}

struct thread_work {
	int iterations;
	int failed;
};

static void *run_thread(void *opaque)
{
	struct thread_work *work = opaque;
	volatile long last_pid = 0;
	for (int i = 0; i < work->iterations; i++) {
		last_pid = syscall(SYS_getpid);
		if (last_pid < 0) {
			work->failed = 1;
			break;
		}
	}
	return NULL;
}

static int run_threads(int thread_count, int iterations)
{
	pthread_t threads[16];
	struct thread_work work[16];
	if (thread_count < 1 || thread_count > 16) {
		return 1;
	}
	for (int i = 0; i < thread_count; i++) {
		work[i] = (struct thread_work) {.iterations = iterations, .failed = 0};
		if (pthread_create(&threads[i], NULL, run_thread, &work[i]) != 0) {
			return 2;
		}
	}
	for (int i = 0; i < thread_count; i++) {
		if (pthread_join(threads[i], NULL) != 0 || work[i].failed) {
			return 3;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		return 64;
	}
	usleep(100000);
	if (strcmp(argv[1], "scalar") == 0) {
		return run_scalar(argc > 2 ? parse_count(argv[2], 1500) : 1500);
	}
	if (strcmp(argv[1], "io") == 0) {
		return run_io(argc > 2 ? parse_count(argv[2], 1000) : 1000);
	}
	if (strcmp(argv[1], "lifecycle") == 0) {
		return run_lifecycle(argc > 2 ? parse_count(argv[2], 8) : 8);
	}
	if (strcmp(argv[1], "threads") == 0) {
		int thread_count = argc > 2 ? parse_count(argv[2], 4) : 4;
		int iterations = argc > 3 ? parse_count(argv[3], 400) : 400;
		return run_threads(thread_count, iterations);
	}
	return 65;
}
