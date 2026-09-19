#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXTURE_SYS_OPEN_TREE 428
#define FIXTURE_SYS_MOVE_MOUNT 429
#define FIXTURE_OPEN_TREE_CLONE 1U
#define FIXTURE_OPEN_TREE_CLOEXEC O_CLOEXEC
#define FIXTURE_MOVE_MOUNT_F_SYMLINKS 1U
#define FIXTURE_MOVE_MOUNT_BENEATH 0x200U

static inline void touch_memory(const void *p)
{
	asm volatile ("" : : "r"(*(const volatile char *)p) : "memory");
}

int main(void)
{
	static const char source[] = "/dev/full";
	static const char target[] = "/tmp/strace-go-ebpf-move-target";
	touch_memory(source);
	touch_memory(target);
	unsigned int open_flags = FIXTURE_OPEN_TREE_CLONE |
		FIXTURE_OPEN_TREE_CLOEXEC;
	long tree_fd = syscall(FIXTURE_SYS_OPEN_TREE, AT_FDCWD, source,
		open_flags);
	if (tree_fd >= 0) {
		(void) close((int) tree_fd);
	}

	unsigned int move_flags = FIXTURE_MOVE_MOUNT_F_SYMLINKS |
		FIXTURE_MOVE_MOUNT_BENEATH;
	(void) syscall(FIXTURE_SYS_MOVE_MOUNT, AT_FDCWD, source,
		AT_FDCWD, target, move_flags);

	puts("mount-path-fixture-ok");
	return 0;
}
