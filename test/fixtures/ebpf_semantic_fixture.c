#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int current_tracer_pid(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	if (!f) {
		return -1;
	}

	char line[128];
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "TracerPid:", 10) == 0) {
			fclose(f);
			return atoi(line + 10);
		}
	}
	fclose(f);
	return -1;
}

static int run_semantic_fixture(void)
{
	char buf[16];

	usleep(100000);

	int tracer_pid = current_tracer_pid();
	if (tracer_pid != 0) {
		fprintf(stderr, "unexpected TracerPid=%d\n", tracer_pid);
		return 70;
	}

	int fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		ssize_t nread = read(fd, buf, sizeof(buf));
		(void) nread;
		(void) close(fd);
	}

	int missing = open("/tmp/strace-go-ebpf-missing-file", O_RDONLY);
	if (missing >= 0) {
		(void) close(missing);
	}

	ssize_t nwritten = write(STDOUT_FILENO, "ebpf-fixture-write\n", 19);
	(void) nwritten;

	pid_t child = fork();
	if (child == 0) {
		execl("/bin/true", "true", (char *) NULL);
		_exit(127);
	}
	if (child > 0) {
		int status = 0;
		(void) waitpid(child, &status, 0);
	}

	return 0;
}

static int run_perf_fixture(void)
{
	volatile pid_t sink = 0;

	usleep(100000);
	for (int i = 0; i < 5000; i++) {
		sink = getpid();
	}

	return sink == 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "perf") == 0) {
		return run_perf_fixture();
	}
	return run_semantic_fixture();
}
