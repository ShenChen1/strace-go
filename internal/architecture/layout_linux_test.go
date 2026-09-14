package architecture

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestNativeBPFLayout(t *testing.T) {
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("ABI contract tests require clang")
	}
	_, file, _, _ := runtime.Caller(0)
	header := filepath.Join(filepath.Dir(file), "../../bpf/native_abi_layout.h")
	target := "x86"
	if runtime.GOARCH == "arm64" {
		target = "arm64"
	}
	source := fmt.Sprintf("#include %q\n_Static_assert(NATIVE_STAT_SIZE == %d, \"stat\");\n_Static_assert(NATIVE_EPOLL_EVENT_SIZE == %d, \"epoll\");\n_Static_assert(NATIVE_EPOLL_DATA_OFFSET == %d, \"epoll data\");\n", header, StatSize, EpollEventSize, EpollDataOffset)
	cmd := exec.Command(cc, "-x", "c", "-fsyntax-only", "-D__TARGET_ARCH_"+target, "-")
	cmd.Stdin = strings.NewReader(source)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("BPF/native ABI mismatch: %v\n%s", err, out)
	}
}

func TestSharedNativeLayouts(t *testing.T) {
	tests := map[string]struct{ got, want uintptr }{
		"pointer":        {unsafe.Sizeof(uintptr(0)), 8},
		"iovec":          {unsafe.Sizeof(unix.Iovec{}), 16},
		"iovec.len":      {unsafe.Offsetof(unix.Iovec{}.Len), 8},
		"msghdr":         {unsafe.Sizeof(unix.Msghdr{}), 56},
		"msghdr.iov":     {unsafe.Offsetof(unix.Msghdr{}.Iov), 16},
		"msghdr.control": {unsafe.Offsetof(unix.Msghdr{}.Control), 32},
		"msghdr.flags":   {unsafe.Offsetof(unix.Msghdr{}.Flags), 48},
		"cmsghdr":        {unsafe.Sizeof(unix.Cmsghdr{}), 16},
		"pollfd":         {unsafe.Sizeof(unix.PollFd{}), 8},
		"timespec":       {unsafe.Sizeof(unix.Timespec{}), 16},
		"timeval":        {unsafe.Sizeof(unix.Timeval{}), 16},
		"timex":          {unsafe.Sizeof(unix.Timex{}), 208},
		"statfs":         {unsafe.Sizeof(unix.Statfs_t{}), 120},
		"statx":          {unsafe.Sizeof(unix.Statx_t{}), 256},
		"flock":          {unsafe.Sizeof(unix.Flock_t{}), 32},
		"open_how":       {unsafe.Sizeof(unix.OpenHow{}), 24},
		"sockaddr_in":    {unsafe.Sizeof(unix.RawSockaddrInet4{}), 16},
		"sockaddr_in6":   {unsafe.Sizeof(unix.RawSockaddrInet6{}), 28},
		"stat.size":      {unsafe.Offsetof(unix.Stat_t{}.Size), 48},
		"stat.blksize":   {unsafe.Offsetof(unix.Stat_t{}.Blksize), 56},
		"stat.blocks":    {unsafe.Offsetof(unix.Stat_t{}.Blocks), 64},
		"stat.atim":      {unsafe.Offsetof(unix.Stat_t{}.Atim), 72},
		"stat.mtim":      {unsafe.Offsetof(unix.Stat_t{}.Mtim), 88},
		"stat.ctim":      {unsafe.Offsetof(unix.Stat_t{}.Ctim), 104},
	}
	for name, test := range tests {
		if test.got != test.want {
			t.Errorf("%s: %d, want %d", name, test.got, test.want)
		}
	}
}
