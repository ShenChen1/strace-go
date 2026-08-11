#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MMSG_COUNT 5

static int send_messages(int fd)
{
	static const char text[MMSG_COUNT][8] = {
		"mmsg-a", "mmsg-b", "mmsg-c", "mmsg-d", "mmsg-e"
	};
	struct iovec iov[MMSG_COUNT];
	struct mmsghdr messages[MMSG_COUNT];

	memset(messages, 0, sizeof(messages));
	for (size_t i = 0; i < MMSG_COUNT; i++) {
		iov[i].iov_base = (void *)text[i];
		iov[i].iov_len = strlen(text[i]);
		messages[i].msg_hdr.msg_iov = &iov[i];
		messages[i].msg_hdr.msg_iovlen = 1;
	}

	long result = syscall(SYS_sendmmsg, fd, messages, MMSG_COUNT, 0);
	return result == MMSG_COUNT ? 0 : -1;
}

static int receive_messages(int fd)
{
	char buffers[MMSG_COUNT][16];
	struct iovec iov[MMSG_COUNT];
	struct mmsghdr messages[MMSG_COUNT];

	memset(buffers, 0, sizeof(buffers));
	memset(messages, 0, sizeof(messages));
	for (size_t i = 0; i < MMSG_COUNT; i++) {
		iov[i].iov_base = buffers[i];
		iov[i].iov_len = sizeof(buffers[i]);
		messages[i].msg_hdr.msg_iov = &iov[i];
		messages[i].msg_hdr.msg_iovlen = 1;
	}

	long result = syscall(
		SYS_recvmmsg, fd, messages, MMSG_COUNT, MSG_DONTWAIT, NULL);
	return result == MMSG_COUNT ? 0 : -1;
}

int main(void)
{
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) {
		perror("socketpair");
		return 1;
	}
	if (send_messages(sockets[0]) != 0 || receive_messages(sockets[1]) != 0) {
		perror("mmsg");
		return 2;
	}
	close(sockets[0]);
	close(sockets[1]);
	puts("mmsg-fixture-ok");
	return 0;
}
