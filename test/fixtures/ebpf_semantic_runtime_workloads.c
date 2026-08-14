#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ebpf_semantic_fixture.h"

#define FIXTURE_SYS_FUTEX_WAITV 449

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

static int run_itimer_fixture(void)
{
	struct itimerval current;
	if (syscall(SYS_getitimer, ITIMER_REAL, &current) != 0) {
		perror("getitimer");
		return 99;
	}

	struct itimerval zero;
	memset(&zero, 0, sizeof(zero));
	struct itimerval old;
	if (syscall(SYS_setitimer, ITIMER_REAL, &zero, &old) != 0) {
		perror("setitimer");
		return 100;
	}
	return 0;
}

static int run_time_setter_fixture(void)
{
	struct timespec invalid_ts;
	invalid_ts.tv_sec = 0;
	invalid_ts.tv_nsec = 1000000000L;
	if (syscall(SYS_clock_settime, CLOCK_REALTIME, &invalid_ts) == 0) {
		fprintf(stderr, "unexpected clock_settime success\n");
		return 101;
	}

	struct timeval invalid_tv;
	invalid_tv.tv_sec = -1;
	invalid_tv.tv_usec = 1000000;
	struct timezone tz;
	memset(&tz, 0, sizeof(tz));
	if (syscall(SYS_settimeofday, &invalid_tv, &tz) == 0) {
		fprintf(stderr, "unexpected settimeofday success\n");
		return 102;
	}
	return 0;
}

static int run_timex_fixture(void)
{
	struct timex tx;
	memset(&tx, 0, sizeof(tx));
	if (syscall(SYS_adjtimex, &tx) < 0) {
		perror("adjtimex");
		return 103;
	}
	return 0;
}

static int run_sleep_fixture(void)
{
	struct timespec zero;
	memset(&zero, 0, sizeof(zero));
	if (syscall(SYS_nanosleep, &zero, NULL) != 0) {
		perror("nanosleep");
		return 104;
	}
	if (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &zero, NULL) != 0) {
		perror("clock_nanosleep");
		return 105;
	}
	return 0;
}

static int run_futex_fixture(void)
{
	int futex_word = 0;
	struct timespec zero;
	memset(&zero, 0, sizeof(zero));
	errno = 0;
	long rc = syscall(SYS_futex, &futex_word, FUTEX_WAIT, 0, &zero, NULL, 0);
	if (rc != -1 || errno != ETIMEDOUT) {
		fprintf(stderr, "unexpected futex rc=%ld errno=%d\n", rc, errno);
		return 106;
	}
	return 0;
}

static int run_futex2_fixture(void)
{
	int futex_a = 0;
	int futex_b = 0;
	struct timespec zero;
	memset(&zero, 0, sizeof(zero));

	errno = 0;
	long rc = syscall(SYS_futex_wait, &futex_a, 1UL, 0xffffffffUL, FUTEX2_SIZE_U32, &zero, CLOCK_MONOTONIC);
	if (rc != -1 || (errno != EAGAIN && errno != ENOSYS)) {
		fprintf(stderr, "unexpected futex_wait rc=%ld errno=%d\n", rc, errno);
		return 107;
	}

	struct futex_waitv waiters[2];
	memset(waiters, 0, sizeof(waiters));
	waiters[0].val = 1;
	waiters[0].uaddr = (unsigned long) &futex_a;
	waiters[0].flags = FUTEX2_SIZE_U32;
	waiters[1].val = 1;
	waiters[1].uaddr = (unsigned long) &futex_b;
	waiters[1].flags = FUTEX2_SIZE_U32;

	errno = 0;
	rc = syscall(FIXTURE_SYS_FUTEX_WAITV, waiters, 2U, 0U, &zero, CLOCK_MONOTONIC);
	if (rc < 0 && errno != EAGAIN && errno != ETIMEDOUT && errno != EINVAL && errno != ENOSYS) {
		fprintf(stderr, "unexpected futex_waitv rc=%ld errno=%d\n", rc, errno);
		return 108;
	}

	errno = 0;
	rc = syscall(SYS_futex_requeue, waiters, FUTEX2_SIZE_U32, 0U, 0U);
	if (rc < 0 && errno != EAGAIN && errno != EINVAL && errno != ENOSYS) {
		fprintf(stderr, "unexpected futex_requeue rc=%ld errno=%d\n", rc, errno);
		return 109;
	}
	return 0;
}

static int run_msg_control_fixture(void)
{
	char control[CMSG_SPACE(sizeof(int))];
	memset(control, 0, sizeof(control));

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "missing cmsghdr\n");
		return 110;
	}
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	int fd = -1;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	errno = 0;
	long rc = syscall(SYS_sendmsg, -1, &msg, 0);
	if (rc != -1 || errno != EBADF) {
		fprintf(stderr, "unexpected sendmsg control rc=%ld errno=%d\n", rc, errno);
		return 111;
	}
	return 0;
}

static void run_large_io_fixture(void)
{
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
		char buf[32];
		(void) unlink(template);
		(void) syscall(SYS_pwrite64, rwfd, "ebpf-fixture-pwrite\n", 20, 0);
		(void) syscall(SYS_pread64, rwfd, buf, sizeof(buf), 0);
		(void) close(rwfd);
	}
}

static void run_exec_fixture(void)
{
	pid_t child = fork();
	if (child == 0) {
		execl("/bin/true", "true", (char *) NULL);
		_exit(127);
	}
	if (child > 0) {
		int status = 0;
		(void) waitpid(child, &status, 0);
	}
}

int run_semantic_runtime_workloads(void)
{
	int status = run_itimer_fixture();
	if (status != 0) {
		return status;
	}
	status = run_time_setter_fixture();
	if (status != 0) {
		return status;
	}
	status = run_timex_fixture();
	if (status != 0) {
		return status;
	}
	status = run_sleep_fixture();
	if (status != 0) {
		return status;
	}
	status = run_futex_fixture();
	if (status != 0) {
		return status;
	}
	status = run_futex2_fixture();
	if (status != 0) {
		return status;
	}
	status = run_msg_control_fixture();
	if (status != 0) {
		return status;
	}
	run_large_io_fixture();
	run_exec_fixture();
	return 0;
}
