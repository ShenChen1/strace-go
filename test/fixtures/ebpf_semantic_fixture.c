#define _GNU_SOURCE

#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FIXTURE_SYS_FUTEX_WAITV 449

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

static int run_readlink_fixture(void)
{
	char link_template[] = "/tmp/strace-go-ebpf-readlink-XXXXXX";
	int fd = mkstemp(link_template);
	if (fd < 0) {
		perror("mkstemp readlink");
		return 79;
	}
	(void) close(fd);
	(void) unlink(link_template);
	if (symlink("/proc/self", link_template) != 0) {
		perror("symlink");
		return 80;
	}

	char link_buf[128];
	if (syscall(SYS_readlink, link_template, link_buf, sizeof(link_buf)) < 0) {
		perror("readlink");
		(void) unlink(link_template);
		return 81;
	}
	if (syscall(SYS_readlinkat, AT_FDCWD, link_template, link_buf, sizeof(link_buf)) < 0) {
		perror("readlinkat");
		(void) unlink(link_template);
		return 82;
	}
	(void) unlink(link_template);
	return 0;
}

static int run_getcwd_fixture(void)
{
	char cwd_buf[512];
	if (syscall(SYS_getcwd, cwd_buf, sizeof(cwd_buf)) < 0) {
		perror("getcwd");
		return 83;
	}
	return 0;
}

static int run_openat2_fixture(void)
{
	struct open_how how = {0};
	how.flags = O_RDONLY;
	int fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
	if (fd < 0) {
		perror("openat2");
		return 116;
	}
	if (close(fd) != 0) {
		perror("close openat2");
		return 117;
	}
	return 0;
}

static int run_fd_array_fixture(void)
{
	int pipe_fds[2] = {-1, -1};
	if (syscall(SYS_pipe, pipe_fds) != 0) {
		perror("pipe");
		return 84;
	}
	(void) close(pipe_fds[0]);
	(void) close(pipe_fds[1]);

	int pipe2_fds[2] = {-1, -1};
	if (syscall(SYS_pipe2, pipe2_fds, O_CLOEXEC) != 0) {
		perror("pipe2");
		return 85;
	}
	(void) close(pipe2_fds[0]);
	(void) close(pipe2_fds[1]);

	int socket_fds[2] = {-1, -1};
	if (syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, socket_fds) != 0) {
		perror("socketpair");
		return 86;
	}
	(void) close(socket_fds[0]);
	(void) close(socket_fds[1]);
	return 0;
}

static int run_dup_fixture(void)
{
	int source_fd = open("/dev/null", O_RDONLY);
	if (source_fd < 0) {
		perror("open dup source");
		return 112;
	}

	int dup_fd = syscall(SYS_dup, source_fd);
	if (dup_fd < 0) {
		perror("dup");
		(void) close(source_fd);
		return 113;
	}

	int dup2_fd = syscall(SYS_dup2, source_fd, dup_fd + 10);
	if (dup2_fd < 0) {
		perror("dup2");
		(void) close(dup_fd);
		(void) close(source_fd);
		return 114;
	}

	int dup3_fd = syscall(SYS_dup3, source_fd, dup2_fd + 10, O_CLOEXEC);
	if (dup3_fd < 0) {
		perror("dup3");
		(void) close(dup2_fd);
		(void) close(dup_fd);
		(void) close(source_fd);
		return 115;
	}

	(void) close(dup3_fd);
	(void) close(dup2_fd);
	(void) close(dup_fd);
	(void) close(source_fd);
	return 0;
}

static int run_misc_struct_fixture(void)
{
	struct utsname uts;
	if (syscall(SYS_uname, &uts) != 0) {
		perror("uname");
		return 87;
	}

	struct sysinfo info;
	if (syscall(SYS_sysinfo, &info) != 0) {
		perror("sysinfo");
		return 88;
	}

	struct rlimit limit;
	if (syscall(SYS_getrlimit, RLIMIT_NOFILE, &limit) != 0) {
		perror("getrlimit");
		return 89;
	}
	if (syscall(SYS_setrlimit, RLIMIT_NOFILE, &limit) != 0) {
		perror("setrlimit");
		return 90;
	}

	struct rlimit old_limit;
	if (syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limit, &old_limit) != 0) {
		perror("prlimit64");
		return 91;
	}
	return 0;
}

static int run_small_struct_fixture(void)
{
	unsigned long fs_base = 0;
	if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base) != 0) {
		perror("arch_prctl");
		return 92;
	}

	struct robust_list_head *head = NULL;
	size_t robust_len = 0;
	if (syscall(SYS_get_robust_list, 0, &head, &robust_len) != 0) {
		perror("get_robust_list");
		return 93;
	}

	char src_template[] = "/tmp/strace-go-ebpf-small-src-XXXXXX";
	int src_fd = mkstemp(src_template);
	if (src_fd < 0) {
		perror("mkstemp small src");
		return 94;
	}
	(void) unlink(src_template);
	if (write(src_fd, "small-struct-fixture\n", 21) != 21) {
		perror("write small src");
		(void) close(src_fd);
		return 95;
	}
	if (lseek(src_fd, 0, SEEK_SET) < 0) {
		perror("lseek small src");
		(void) close(src_fd);
		return 96;
	}

	int null_fd = open("/dev/null", O_WRONLY);
	if (null_fd < 0) {
		perror("open /dev/null write");
		(void) close(src_fd);
		return 97;
	}
	off_t sendfile_offset = 0;
	if (syscall(SYS_sendfile, null_fd, src_fd, &sendfile_offset, 4) < 0) {
		perror("sendfile");
		(void) close(null_fd);
		(void) close(src_fd);
		return 98;
	}
	(void) close(null_fd);

	char dst_template[] = "/tmp/strace-go-ebpf-small-dst-XXXXXX";
	int dst_fd = mkstemp(dst_template);
	if (dst_fd >= 0) {
		(void) unlink(dst_template);
		long long off_in = 0;
		long long off_out = 0;
		(void) syscall(SYS_copy_file_range, src_fd, &off_in, dst_fd, &off_out, 4, 0);
		(void) close(dst_fd);
	}
	(void) close(src_fd);
	return 0;
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
		struct stat st;
		if (syscall(SYS_fstat, fd, &st) != 0) {
			perror("fstat");
			return 73;
		}
		struct statfs sfs;
		if (syscall(SYS_fstatfs, fd, &sfs) != 0) {
			perror("fstatfs");
			return 74;
		}
		(void) close(fd);
	}

	int openat2_status = run_openat2_fixture();
	if (openat2_status != 0) {
		return openat2_status;
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

	struct statfs path_sfs;
	if (syscall(SYS_statfs, "/proc/self", &path_sfs) != 0) {
		perror("statfs");
		return 75;
	}
	struct stat path_st;
	if (syscall(SYS_stat, "/proc/self", &path_st) != 0) {
		perror("stat");
		return 76;
	}
	if (syscall(SYS_lstat, "/proc/self", &path_st) != 0) {
		perror("lstat");
		return 77;
	}
	if (syscall(SYS_newfstatat, AT_FDCWD, "/proc/self", &path_st, 0) != 0) {
		perror("newfstatat");
		return 78;
	}
	int readlink_status = run_readlink_fixture();
	if (readlink_status != 0) {
		return readlink_status;
	}
	int getcwd_status = run_getcwd_fixture();
	if (getcwd_status != 0) {
		return getcwd_status;
	}
	int fd_array_status = run_fd_array_fixture();
	if (fd_array_status != 0) {
		return fd_array_status;
	}
	int dup_status = run_dup_fixture();
	if (dup_status != 0) {
		return dup_status;
	}
	int misc_struct_status = run_misc_struct_fixture();
	if (misc_struct_status != 0) {
		return misc_struct_status;
	}
	int small_struct_status = run_small_struct_fixture();
	if (small_struct_status != 0) {
		return small_struct_status;
	}
	int itimer_status = run_itimer_fixture();
	if (itimer_status != 0) {
		return itimer_status;
	}
	int time_setter_status = run_time_setter_fixture();
	if (time_setter_status != 0) {
		return time_setter_status;
	}
	int timex_status = run_timex_fixture();
	if (timex_status != 0) {
		return timex_status;
	}
	int sleep_status = run_sleep_fixture();
	if (sleep_status != 0) {
		return sleep_status;
	}
	int futex_status = run_futex_fixture();
	if (futex_status != 0) {
		return futex_status;
	}
	int futex2_status = run_futex2_fixture();
	if (futex2_status != 0) {
		return futex2_status;
	}
	int msg_control_status = run_msg_control_fixture();
	if (msg_control_status != 0) {
		return msg_control_status;
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
