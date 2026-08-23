#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_tracer_pid(void)
{
	char status[8192];
	int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	ssize_t size = read(fd, status, sizeof(status) - 1);
	(void) close(fd);
	if (size <= 0) {
		return -1;
	}
	status[size] = '\0';

	const char *field = strstr(status, "TracerPid:");
	if (field == NULL) {
		return -1;
	}
	int tracer_pid = -1;
	if (sscanf(field, "TracerPid: %d", &tracer_pid) != 1) {
		return -1;
	}
	return tracer_pid;
}

int main(void)
{
	/* Give the tracer time to finish its non-stop BPF bootstrap. */
	(void) usleep(100000);
	int tracer_pid = read_tracer_pid();
	printf("TracerPid: %d\n", tracer_pid);
	if (tracer_pid < 0) {
		fprintf(stderr, "unable to read TracerPid\n");
		return 70;
	}
	if (tracer_pid != 0) {
		fprintf(stderr, "unexpected tracer pid: %d\n", tracer_pid);
		return 71;
	}
	puts("no-ptrace-fixture-ok");
	return 0;
}
