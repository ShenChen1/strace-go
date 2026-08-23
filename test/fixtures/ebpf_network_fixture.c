#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void init_loopback_address(struct sockaddr_in *address)
{
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address->sin_port = htons(0);
}

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		(void)syscall(SYS_close, *fd);
		*fd = -1;
	}
}

static int create_bound_socket(int type, struct sockaddr_in *address)
{
	int fd = (int)syscall(SYS_socket, AF_INET, type, 0);
	if (fd < 0) {
		return -1;
	}
	init_loopback_address(address);
	if (syscall(SYS_bind, fd, address, sizeof(*address)) < 0) {
		close_fd(&fd);
		return -1;
	}
	socklen_t address_len = sizeof(*address);
	if (syscall(SYS_getsockname, fd, address, &address_len) < 0) {
		close_fd(&fd);
		return -1;
	}
	return fd;
}

static int run_tcp_connection(
	int listener,
	const struct sockaddr_in *address,
	int use_accept4)
{
	int client = -1;
	int accepted = -1;
	struct sockaddr_in peer = {};
	struct sockaddr_in local = {};
	client = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
	if (client < 0 || syscall(SYS_connect, client, address, sizeof(*address)) < 0) {
		goto fail;
	}
	socklen_t peer_len = sizeof(peer);
	if (use_accept4) {
		accepted = (int)syscall(
			SYS_accept4, listener, &peer, &peer_len, SOCK_CLOEXEC);
	} else {
		accepted = (int)syscall(SYS_accept, listener, &peer, &peer_len);
	}
	if (accepted < 0) {
		goto fail;
	}
	socklen_t local_len = sizeof(local);
	if (syscall(SYS_getsockname, accepted, &local, &local_len) < 0 ||
		syscall(SYS_getpeername, client, &local, &local_len) < 0) {
		goto fail;
	}
	close_fd(&accepted);
	close_fd(&client);
	return 0;

fail:
	close_fd(&accepted);
	close_fd(&client);
	return 1;
}

static int run_tcp_workload(void)
{
	int listener = -1;
	struct sockaddr_in address = {};
	listener = create_bound_socket(SOCK_STREAM, &address);
	if (listener < 0 || syscall(SYS_listen, listener, 2) < 0) {
		goto fail;
	}
	if (run_tcp_connection(listener, &address, 0) != 0 ||
		run_tcp_connection(listener, &address, 1) != 0) {
		goto fail;
	}
	close_fd(&listener);
	return 0;

fail:
	close_fd(&listener);
	return 1;
}

static int run_udp_workload(void)
{
	int server = -1;
	int sender = -1;
	struct sockaddr_in address = {};
	struct sockaddr_in peer = {};
	char received[64] = {};
	const char marker[] = "ebpf-network-payload";
	socklen_t peer_len = sizeof(peer);
	server = create_bound_socket(SOCK_DGRAM, &address);
	sender = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
	if (server < 0 || sender < 0) {
		goto fail;
	}
	long sent = syscall(
		SYS_sendto, sender, marker, sizeof(marker) - 1, 0,
		&address, sizeof(address));
	long received_len = syscall(
		SYS_recvfrom, server, received, sizeof(received), 0,
		&peer, &peer_len);
	if (sent != (long)(sizeof(marker) - 1) ||
		received_len != (long)(sizeof(marker) - 1) ||
		memcmp(received, marker, sizeof(marker) - 1) != 0) {
		goto fail;
	}
	close_fd(&sender);
	close_fd(&server);
	return 0;

fail:
	close_fd(&sender);
	close_fd(&server);
	return 1;
}

static int run_failure_workload(void)
{
	struct sockaddr_in address = {};
	char buffer[] = "bad-network-call";
	struct sockaddr_in peer = {};
	socklen_t peer_len = sizeof(peer);
	init_loopback_address(&address);
	long connect_result = syscall(SYS_connect, -1, &address, sizeof(address));
	int connect_errno = errno;
	long send_result = syscall(
		SYS_sendto, -1, buffer, sizeof(buffer) - 1, 0,
		&address, sizeof(address));
	int send_errno = errno;
	long recv_result = syscall(
		SYS_recvfrom, -1, buffer, sizeof(buffer), 0,
		&peer, &peer_len);
	int recv_errno = errno;
	return connect_result == -1 && connect_errno == EBADF &&
		send_result == -1 && send_errno == EBADF &&
		recv_result == -1 && recv_errno == EBADF ? 0 : 1;
}

static int run_network_fixture(void)
{
	if (run_tcp_workload() != 0) {
		return 1;
	}
	if (run_udp_workload() != 0) {
		return 2;
	}
	if (run_failure_workload() != 0) {
		return 3;
	}
	puts("network-fixture-ok");
	return 0;
}

int main(void)
{
	return run_network_fixture();
}
