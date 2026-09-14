package format_test

import (
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func nativeBytes[T any](value *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(value)), int(unsafe.Sizeof(*value)))
}

func TestStatNativeLayout(t *testing.T) {
	value := unix.Stat_t{Ino: 42, Mode: 0100640, Nlink: 3, Uid: 123, Gid: 456, Blksize: 4096}
	got := format.StatWithCatalog(meta.NewCatalog("abbrev"), nativeBytes(&value))
	for _, want := range []string{"st_ino=42,", "st_mode=S_IFREG|0640,", "st_nlink=3,", "st_uid=123,", "st_gid=456,", "st_blksize=4096,"} {
		if !strings.Contains(got, want) {
			t.Errorf("stat = %q, missing %q", got, want)
		}
	}
	if got := format.StatWithCatalog(meta.NewCatalog("abbrev"), nativeBytes(&value)[:unsafe.Sizeof(value)-1]); got != "{...}" {
		t.Fatalf("short native stat decoded: %s", got)
	}
}

func TestEpollNativeLayout(t *testing.T) {
	values := [2]unix.EpollEvent{{Events: unix.EPOLLIN, Fd: 17}, {Events: unix.EPOLLOUT, Fd: 29}}
	catalog := meta.NewCatalog("abbrev")
	got := format.EpollEventsWithCatalog(catalog, nativeBytes(&values), 2)
	for _, want := range []string{"events=EPOLLIN, data={u32=17,", "events=EPOLLOUT, data={u32=29,"} {
		if !strings.Contains(got, want) {
			t.Errorf("events = %q, missing %q", got, want)
		}
	}
	if got := format.EpollEventWithCatalog(catalog, nativeBytes(&values[0])); !strings.Contains(got, "u32=17,") {
		t.Fatalf("event = %q", got)
	}
	if got := format.EpollEventWithCatalog(catalog, nativeBytes(&values[0])[:unsafe.Sizeof(values[0])-1]); got != "{...}" {
		t.Fatalf("short native event decoded: %s", got)
	}
}
