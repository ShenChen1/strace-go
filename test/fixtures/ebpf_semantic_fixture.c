#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
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

static void fill_large_write_payload(char *buf, size_t len)
{
	const char prefix[] = "ebpf-large-write-";
	size_t prefix_len = sizeof(prefix) - 1;

	if (len < prefix_len) {
		return;
	}
	memcpy(buf, prefix, prefix_len);
	for (size_t i = prefix_len; i < len; i++) {
		buf[i] = (char) ('A' + (i % 26));
	}
}

static int run_semantic_fixture(void)
{
	char buf[32];

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

	struct timespec ts;
	if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		return 71;
	}

	struct timeval tv;
	struct timezone tz;
	if (syscall(SYS_gettimeofday, &tv, &tz) != 0) {
		perror("gettimeofday");
		return 72;
	}

	char large[1024];
	fill_large_write_payload(large, sizeof(large));
	int null_out = open("/dev/null", O_WRONLY);
	if (null_out >= 0) {
		ssize_t nlarge = write(null_out, large, sizeof(large));
		(void) nlarge;
		(void) close(null_out);
	}

	char template[] = "/tmp/strace-go-ebpf-preadwrite-XXXXXX";
	int rwfd = mkstemp(template);
	if (rwfd >= 0) {
		(void) unlink(template);
		(void) syscall(SYS_pwrite64, rwfd, "ebpf-fixture-pwrite\n", 20, 0);
		(void) syscall(SYS_pread64, rwfd, buf, sizeof(buf), 0);
		(void) close(rwfd);
	}

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
