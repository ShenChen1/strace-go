#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int run_sockopt_fixture(void)
{
	int sockets[2] = {-1, -1};
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
		return 1;
	}

	unsigned char set_value[5] = {1, 0, 0, 0, 0};
	long set_result = syscall(
		SYS_setsockopt, sockets[0], SOL_SOCKET, SO_REUSEADDR,
		set_value, sizeof(set_value));

	int get_value = 0;
	socklen_t get_length = sizeof(get_value) + 1;
	long get_result = syscall(
		SYS_getsockopt, sockets[0], SOL_SOCKET, SO_REUSEADDR,
		&get_value, &get_length);

	long bad_set = syscall(
		SYS_setsockopt, -1, SOL_SOCKET, SO_REUSEADDR,
		set_value, sizeof(int));
	long bad_get = syscall(
		SYS_getsockopt, -1, SOL_SOCKET, SO_REUSEADDR,
		&get_value, &get_length);

	(void) close(sockets[0]);
	(void) close(sockets[1]);
	if (set_result != 0 || get_result != 0 || bad_set != -1 || bad_get != -1) {
		return 2;
	}
	if (get_length != sizeof(get_value) || get_value != 1) {
		return 3;
	}
	puts("sockopt-fixture-ok");
	return 0;
}

int main(void)
{
	return run_sockopt_fixture();
}
