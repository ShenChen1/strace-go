#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
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
	int misc_struct_status = run_misc_struct_fixture();
	if (misc_struct_status != 0) {
		return misc_struct_status;
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
