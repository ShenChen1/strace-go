package main

import "testing"

func TestDynamicSizeStrUsesEpollEventSize(t *testing.T) {
	want := "((e)->ret > 0 ? ((e)->ret * 12 > 512 ? 512 : (e)->ret * 12) : 0)"
	for _, syscall := range []string{"epoll_wait", "epoll_pwait", "epoll_pwait2"} {
		got := dynamicSizeStr(syscall, "exit", CaptureRead{Arg: 1})
		if got != want {
			t.Fatalf("dynamicSizeStr(%q) = %q, want %q", syscall, got, want)
		}
	}
}

func TestDynamicSizeStrKeepsDefaultExitSize(t *testing.T) {
	got := dynamicSizeStr("unknown", "exit", CaptureRead{Arg: 1})
	want := "((e)->ret > 0 ? ((e)->ret * 32 > 512 ? 512 : (e)->ret * 32) : 0)"
	if got != want {
		t.Fatalf("dynamicSizeStr() = %q, want %q", got, want)
	}
}

func TestDynamicSizeStrUsesPollNfds(t *testing.T) {
	want := "((e)->args[1] > 0 ? ((e)->args[1] * 8 > 512 ? 512 : (e)->args[1] * 8) : 0)"
	for _, syscall := range []string{"poll", "ppoll"} {
		got := dynamicSizeStr(syscall, "exit", CaptureRead{Arg: 0})
		if got != want {
			t.Fatalf("dynamicSizeStr(%q) = %q, want %q", syscall, got, want)
		}
	}
}

func TestCaptureSizeExprUsesPayloadArgLength(t *testing.T) {
	lenArg := 2
	read := CaptureRead{Arg: 1, LenFromArg: &lenArg, Max: 512}
	got := captureSizeExpr("write", "enter", read)
	want := "((e)->args[2] > 0 ? ((e)->args[2] > 512 ? 512 : (e)->args[2]) : 0)"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}

func TestCaptureSizeExprUsesPayloadRetLength(t *testing.T) {
	read := CaptureRead{Arg: 1, LenFromRet: true, Max: 512}
	got := captureSizeExpr("read", "exit", read)
	want := "((e)->ret > 0 ? ((e)->ret > 512 ? 512 : (e)->ret) : 0)"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}
