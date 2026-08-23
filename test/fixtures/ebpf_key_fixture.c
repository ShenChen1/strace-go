#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
	static const char type[] = "user";
	static const char add_description[] = "ebpf-key-add";
	static const char add_payload[] = "ebpf-key-payload";
	static const char request_description[] = "ebpf-key-request";
	static const char callout_info[] = "ebpf-key-callout";

	(void)syscall(
		SYS_add_key,
		type,
		add_description,
		add_payload,
		sizeof(add_payload) - 1,
		-1);
	(void)syscall(
		SYS_request_key,
		type,
		request_description,
		callout_info,
		-1);
	puts("key-fixture-ok");
	return 0;
}
