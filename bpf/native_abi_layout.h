#ifndef STRACE_GO_NATIVE_ABI_LAYOUT_H
#define STRACE_GO_NATIVE_ABI_LAYOUT_H

#define NATIVE_KERNEL_TERMIOS_SIZE 36

#if defined(__TARGET_ARCH_x86)
#define NATIVE_STAT_SIZE 144
#define NATIVE_EPOLL_EVENT_SIZE 12
#define NATIVE_EPOLL_DATA_OFFSET 4
#elif defined(__TARGET_ARCH_arm64)
#define NATIVE_STAT_SIZE 128
#define NATIVE_EPOLL_EVENT_SIZE 16
#define NATIVE_EPOLL_DATA_OFFSET 8
#else
#error "unsupported architecture: native amd64 or arm64 required"
#endif

#endif
