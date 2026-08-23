#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail_fixture(const char *step)
{
	fprintf(stderr, "recvmsg fixture failed at %s: errno=%d\n", step, errno);
	return 1;
}

static int send_unix_rights(int fd, int send_fd)
{
	static const char marker[] = "rx-cmsg";
	union {
		struct cmsghdr align;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control = {};
	struct iovec iov = {
		.iov_base = (void *)marker,
		.iov_len = sizeof(marker) - 1,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.bytes,
		.msg_controllen = sizeof(control.bytes),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		errno = EINVAL;
		return -1;
	}
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(send_fd));
	return (int)syscall(SYS_sendmsg, fd, &msg, 0);
}

static int receive_unix_rights(int fd)
{
	static const char marker[] = "rx-cmsg";
	char data[32] = {};
	union {
		struct cmsghdr align;
		unsigned char bytes[128];
	} control = {};
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.bytes,
		.msg_controllen = sizeof(control.bytes),
	};
	int received_fd = -1;
	ssize_t ret = syscall(SYS_recvmsg, fd, &msg, 0);
	if (ret != (ssize_t)(sizeof(marker) - 1) || memcmp(data, marker, sizeof(marker) - 1) != 0) {
		errno = EPROTO;
		return -1;
	}
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
			cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
			continue;
		}
		memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
		break;
	}
	if (received_fd < 0) {
		errno = EPROTO;
		return -1;
	}
	if (syscall(SYS_close, received_fd) < 0) {
		return -1;
	}
	return 0;
}

static int run_unix_fixture(void)
{
	int sockets[2] = {-1, -1};
	if (syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) {
		return fail_fixture("socketpair");
	}
	if (send_unix_rights(sockets[0], sockets[0]) != 7) {
		return fail_fixture("unix sendmsg");
	}
	if (receive_unix_rights(sockets[1]) < 0) {
		return fail_fixture("unix recvmsg");
	}
	if (syscall(SYS_close, sockets[0]) < 0 || syscall(SYS_close, sockets[1]) < 0) {
		return fail_fixture("unix close");
	}
	return 0;
}

static int run_udp_fixture(void)
{
	static const char marker[] = "rx-name";
	int receiver = syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
	int sender = syscall(SYS_socket, AF_INET, SOCK_DGRAM, 0);
	if (receiver < 0 || sender < 0) {
		return fail_fixture("udp socket");
	}
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	if (syscall(SYS_bind, receiver, &address, sizeof(address)) < 0) {
		return fail_fixture("udp bind");
	}
	socklen_t address_len = sizeof(address);
	if (syscall(SYS_getsockname, receiver, &address, &address_len) < 0) {
		return fail_fixture("udp getsockname");
	}
	struct iovec send_iov = {
		.iov_base = (void *)marker,
		.iov_len = sizeof(marker) - 1,
	};
	struct msghdr send_msg = {
		.msg_name = &address,
		.msg_namelen = address_len,
		.msg_iov = &send_iov,
		.msg_iovlen = 1,
	};
	if (syscall(SYS_sendmsg, sender, &send_msg, 0) != (ssize_t)(sizeof(marker) - 1)) {
		return fail_fixture("udp sendmsg");
	}
	char data[32] = {};
	struct sockaddr_storage peer = {};
	struct iovec receive_iov = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr receive_msg = {
		.msg_name = &peer,
		.msg_namelen = sizeof(peer),
		.msg_iov = &receive_iov,
		.msg_iovlen = 1,
	};
	ssize_t ret = syscall(SYS_recvmsg, receiver, &receive_msg, 0);
	if (ret != (ssize_t)(sizeof(marker) - 1) || memcmp(data, marker, sizeof(marker) - 1) != 0 ||
		peer.ss_family != AF_INET) {
		errno = EPROTO;
		return fail_fixture("udp recvmsg");
	}
	if (syscall(SYS_close, sender) < 0 || syscall(SYS_close, receiver) < 0) {
		return fail_fixture("udp close");
	}
	return 0;
}

static int run_failed_recvmsg(void)
{
	char data[8] = {};
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	errno = 0;
	if (syscall(SYS_recvmsg, -1, &msg, 0) != -1 || errno != EBADF) {
		return fail_fixture("failed recvmsg");
	}
	return 0;
}

int main(void)
{
	if (run_unix_fixture() != 0 || run_udp_fixture() != 0 || run_failed_recvmsg() != 0) {
		return 1;
	}
	puts("recvmsg-fixture-ok");
	return 0;
}
