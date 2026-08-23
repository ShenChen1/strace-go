#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char xattr_name[] = "user.fixture";
static const char xattr_value[] = "xattr-value";

static int run_xattr_fixture(void)
{
	char path[] = "/tmp/strace-go-ebpf-xattr-XXXXXX";
	char value_buffer[64] = {};
	char list_buffer[256] = {};
	int fd = mkstemp(path);
	if (fd < 0) {
		return 1;
	}
	(void)syscall(SYS_close, fd);

	long result = syscall(
		SYS_setxattr,
		path,
		xattr_name,
		xattr_value,
		sizeof(xattr_value) - 1,
		0);
	if (result != 0) {
		goto fail;
	}

	result = syscall(
		SYS_getxattr,
		path,
		xattr_name,
		value_buffer,
		sizeof(value_buffer));
	if (result != (long)(sizeof(xattr_value) - 1) ||
		memcmp(value_buffer, xattr_value, sizeof(xattr_value) - 1) != 0) {
		goto fail;
	}

	result = syscall(SYS_listxattr, path, list_buffer, sizeof(list_buffer));
	if (result != (long)sizeof(xattr_name) ||
		memcmp(list_buffer, xattr_name, sizeof(xattr_name)) != 0) {
		goto fail;
	}

	result = syscall(SYS_removexattr, path, xattr_name);
	if (result != 0) {
		goto fail;
	}

	result = syscall(
		SYS_getxattr,
		path,
		xattr_name,
		value_buffer,
		sizeof(value_buffer));
	if (result != -1 || errno != ENODATA) {
		goto fail;
	}

	if (syscall(SYS_unlink, path) != 0) {
		return 2;
	}
	puts("xattr-fixture-ok");
	return 0;

fail:
	(void)syscall(SYS_removexattr, path, xattr_name);
	(void)syscall(SYS_unlink, path);
	return 3;
}

int main(void)
{
	return run_xattr_fixture();
}
