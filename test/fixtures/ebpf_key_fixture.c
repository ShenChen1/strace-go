#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline void touch_memory(const void *p)
{
	asm volatile ("" : : "r"(*(const volatile char *)p) : "memory");
}

int main(void)
{
	char type[] = "user";
	char add_description[] = "ebpf-key-add";
	char add_payload[] = "ebpf-key-payload";
	char request_description[] = "ebpf-key-request";
	char callout_info[] = "ebpf-key-callout";
	touch_memory(type);
	touch_memory(add_description);
	touch_memory(add_payload);
	touch_memory(request_description);
	touch_memory(callout_info);

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
