#define _GNU_SOURCE

#include <asm/prctl.h>
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
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "ebpf_semantic_fixture.h"

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
	if (symlink("ebpf-readlink-target", link_template) != 0) {
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

static int run_path_struct_fixture(void)
{
	char path_template[] = "/tmp/strace-go-ebpf-path-XXXXXX";
	char *path = mkdtemp(path_template);
	if (!path) {
		perror("mkdtemp path");
		return 118;
	}

	struct statfs path_sfs;
	if (syscall(SYS_statfs, path, &path_sfs) != 0) {
		perror("statfs");
		(void) rmdir(path);
		return 119;
	}
	struct stat path_st;
	if (syscall(SYS_stat, path, &path_st) != 0) {
		perror("stat");
		(void) rmdir(path);
		return 120;
	}
	if (syscall(SYS_lstat, path, &path_st) != 0) {
		perror("lstat");
		(void) rmdir(path);
		return 121;
	}
	if (syscall(SYS_newfstatat, AT_FDCWD, path, &path_st, 0) != 0) {
		perror("newfstatat");
		(void) rmdir(path);
		return 122;
	}
	(void) rmdir(path);
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

int run_semantic_fs_workloads(void)
{
	int status = run_openat2_fixture();
	if (status != 0) {
		return status;
	}
	status = run_path_struct_fixture();
	if (status != 0) {
		return status;
	}
	status = run_readlink_fixture();
	if (status != 0) {
		return status;
	}
	status = run_getcwd_fixture();
	if (status != 0) {
		return status;
	}
	status = run_fd_array_fixture();
	if (status != 0) {
		return status;
	}
	status = run_dup_fixture();
	if (status != 0) {
		return status;
	}
	status = run_misc_struct_fixture();
	if (status != 0) {
		return status;
	}
	return run_small_struct_fixture();
}
