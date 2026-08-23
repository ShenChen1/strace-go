#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct aio_sigset_arg {
	uint64_t *sigmask;
	size_t sigsetsize;
};

struct aio_write_request {
	struct iocb iocb;
	const char *buffer;
	uint64_t data;
	int64_t offset;
};

static void close_fd(int *fd)
{
	if (*fd >= 0) {
		(void)syscall(SYS_close, *fd);
		*fd = -1;
	}
}

static int submit_write(
	aio_context_t context,
	int fd,
	struct aio_write_request *request)
{
	struct iocb *requests[1] = {&request->iocb};
	memset(&request->iocb, 0, sizeof(request->iocb));
	request->iocb.aio_data = request->data;
	request->iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
	request->iocb.aio_fildes = (uint32_t)fd;
	request->iocb.aio_buf = (uint64_t)(uintptr_t)request->buffer;
	request->iocb.aio_nbytes = strlen(request->buffer);
	request->iocb.aio_offset = request->offset;
	return syscall(SYS_io_submit, context, 1, requests) == 1 ? 0 : 1;
}

static int wait_for_getevents(
	aio_context_t context,
	uint64_t expected_data,
	size_t expected_size,
	struct io_event *event)
{
	struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
	long result = syscall(SYS_io_getevents, context, 1, 1, event, &timeout);
	return result == 1 && event->data == expected_data &&
		event->res == (int64_t)expected_size && event->res2 == 0 ? 0 : 1;
}

static int wait_for_pgetevents(
	aio_context_t context,
	uint64_t expected_data,
	size_t expected_size,
	struct io_event *event)
{
	struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
	uint64_t sigmask = 1;
	struct aio_sigset_arg sigset = {
		.sigmask = &sigmask,
		.sigsetsize = sizeof(sigmask),
	};
	long result = syscall(
		SYS_io_pgetevents, context, 1, 1, event, &timeout, &sigset);
	return result == 1 && event->data == expected_data &&
		event->res == (int64_t)expected_size && event->res2 == 0 ? 0 : 1;
}

static int run_failure_workload(aio_context_t context)
{
	uint64_t sigmask = 1;
	struct aio_sigset_arg sigset = {
		.sigmask = &sigmask,
		.sigsetsize = sizeof(sigmask),
	};
	long getevents_result = syscall(
		SYS_io_getevents, context, 0, 0, NULL, (void *)(uintptr_t)1);
	int getevents_errno = errno;
	long pgetevents_result = syscall(
		SYS_io_pgetevents, context, 0, 0, NULL, (void *)(uintptr_t)1, &sigset);
	int pgetevents_errno = errno;
	return getevents_result == -1 && getevents_errno == EFAULT &&
		pgetevents_result == -1 && pgetevents_errno == EFAULT ? 0 : 1;
}

int main(void)
{
	char path[] = "/tmp/strace-go-aio-XXXXXX";
	char first_buffer[] = "ebpf-aio-first";
	char second_buffer[] = "ebpf-aio-second";
	struct aio_write_request first_request = {
		.buffer = first_buffer,
		.data = 0x1111,
		.offset = 0,
	};
	struct aio_write_request second_request = {
		.buffer = second_buffer,
		.data = 0x2222,
		.offset = 64,
	};
	struct io_event event = {};
	aio_context_t context = 0;
	int fd = mkstemp(path);
	int status = 0;
	if (fd < 0) {
		return 1;
	}
	(void)unlink(path);
	if (syscall(SYS_io_setup, 8U, &context) != 0) {
		status = 2;
		goto cleanup;
	}
	if (submit_write(context, fd, &first_request) != 0 ||
		wait_for_getevents(context, 0x1111, strlen(first_buffer), &event) != 0) {
		status = 3;
		goto cleanup;
	}
	if (submit_write(context, fd, &second_request) != 0 ||
		wait_for_pgetevents(context, 0x2222, strlen(second_buffer), &event) != 0) {
		status = 4;
		goto cleanup;
	}
	{
		struct io_event cancel_event = {};
		long cancel_result = syscall(
			SYS_io_cancel, context, &second_request.iocb, &cancel_event);
		if (cancel_result >= 0) {
			status = 5;
			goto cleanup;
		}
	}
	if (run_failure_workload(context) != 0) {
		status = 6;
		goto cleanup;
	}

cleanup:
	if (context != 0) {
		if (syscall(SYS_io_destroy, context) != 0 && status == 0) {
			status = 7;
		}
	}
	close_fd(&fd);
	if (status == 0) {
		puts("aio-fixture-ok");
	}
	return status;
}
