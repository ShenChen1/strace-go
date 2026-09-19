#define _GNU_SOURCE

#include <errno.h>
#include <linux/keyctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long keyctl_call(unsigned long operation, unsigned long arg2,
                        unsigned long arg3, unsigned long arg4,
                        unsigned long arg5)
{
	return syscall(SYS_keyctl, operation, arg2, arg3, arg4, arg5);
}

static int require_success(long result, const char *step)
{
	if (result >= 0)
		return 0;
	fprintf(stderr, "%s failed: %s\n", step, strerror(errno));
	return 1;
}

static inline void touch_memory(const void *p)
{
	asm volatile ("" : : "r"(*(const volatile char *)p) : "memory");
}

int main(void)
{
	static const char type[] = "user";
	static const char description[] = "ebpf-keyctl-key";
	static const char update_payload[] = "ebpf-keyctl-update";
	static const char session_name[] = "ebpf-keyctl-session";
	touch_memory(type);
	touch_memory(description);
	touch_memory(update_payload);
	touch_memory(session_name);
	char describe[256] = {};
	char readback[256] = {};
	uint8_t capabilities[64] = {};

	long key = syscall(SYS_add_key, type, description, update_payload,
	                   sizeof(update_payload) - 1, KEY_SPEC_THREAD_KEYRING);
	if (require_success(key, "add_key") != 0)
		return 1;
	if (keyctl_call(KEYCTL_JOIN_SESSION_KEYRING,
	                (unsigned long)session_name, 0, 0, 0) < 0)
		return 2;
	if (keyctl_call(KEYCTL_UPDATE, (unsigned long)key,
	                (unsigned long)update_payload, sizeof(update_payload) - 1, 0) < 0)
		return 3;
	(void)keyctl_call(KEYCTL_SEARCH, KEY_SPEC_THREAD_KEYRING,
	                  (unsigned long)type, (unsigned long)description, 0);
	if (keyctl_call(KEYCTL_DESCRIBE, (unsigned long)key,
	                (unsigned long)describe, sizeof(describe), 0) <= 0)
		return 4;
	if (!strstr(describe, description))
		return 5;
	if (keyctl_call(KEYCTL_READ, (unsigned long)key,
	                (unsigned long)readback, sizeof(readback), 0) !=
	    (long)(sizeof(update_payload) - 1))
		return 6;
	if (memcmp(readback, update_payload, sizeof(update_payload) - 1) != 0)
		return 7;
	if (keyctl_call(KEYCTL_CAPABILITIES, (unsigned long)capabilities,
	                sizeof(capabilities), 0, 0) <= 0)
		return 8;
	(void)keyctl_call(KEYCTL_REVOKE, (unsigned long)key, 0, 0, 0);
	(void)keyctl_call(KEYCTL_REJECT, (unsigned long)key, 30, 0x2000,
	                  KEY_SPEC_THREAD_KEYRING);
	(void)syscall(SYS_request_key, type, description, "ebpf-keyctl-callout",
	              KEY_SPEC_THREAD_KEYRING);
	puts("keyctl-fixture-ok");
	return 0;
}
