package main

import "testing"

func TestDynamicSizeStrDoesNotGuessUnknownSize(t *testing.T) {
	got := dynamicSizeStr("unknown", "exit", CaptureRead{Arg: 1})
	want := "0"
	if got != want {
		t.Fatalf("dynamicSizeStr() = %q, want %q", got, want)
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

func TestCaptureSizeExprUsesPayloadArgMinLength(t *testing.T) {
	lenArg := 3
	read := CaptureRead{Arg: 2, LenFromArg: &lenArg, Min: 24, Max: 64}
	got := captureSizeExpr("openat2", "enter", read)
	want := "((e)->args[3] >= 24 ? ((e)->args[3] > 64 ? 64 : (e)->args[3]) : 0)"
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

func TestCaptureSizeExprUsesPayloadUserArgLength(t *testing.T) {
	lenArg := 2
	read := CaptureRead{Arg: 1, LenFromUserArg: &lenArg, Max: 128}
	got := captureSizeExpr("accept", "exit", read)
	want := "addrlen"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}

func TestCaptureSizeExprUsesPayloadArgBitsLength(t *testing.T) {
	read := CaptureRead{Arg: 2, LenFromArgBits: &ArgBitsLength{Arg: 1, Shift: 16, Mask: 16383, ZeroLen: 128}, Max: 512}
	got := captureSizeExpr("ioctl", "enter", read)
	want := "iosz"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}

func TestCaptureSizeExprUsesPayloadCountLength(t *testing.T) {
	countArg := 2
	read := CaptureRead{Arg: 1, CountFromArg: &countArg, ElemSize: 16, Max: 512}
	got := captureSizeExpr("readv", "enter", read)
	want := "((e)->args[2] > 0 ? ((e)->args[2] * 16 > 512 ? 512 : (e)->args[2] * 16) : 0)"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}

func TestDynamicPreludeUsesPayloadUserArgLength(t *testing.T) {
	lenArg := 2
	clampOffset := 768
	read := CaptureRead{LenFromUserArg: &lenArg, ClampU32FromOffset: &clampOffset, Max: 128}
	got := dynamicPreludeCode("accept", read)
	want := "\t\t\t\tu32 addrlen = 0; \\\n" +
		"\t\t\t\tbpf_probe_read_user(&addrlen, 4, (void *)(e)->args[2]); \\\n" +
		"\t\t\t\tu32 inlen = *(u32 *)((e)->str_arg + 768); \\\n" +
		"\t\t\t\tif (inlen > 0 && inlen < addrlen) addrlen = inlen; \\\n" +
		"\t\t\t\taddrlen = (addrlen > 128) ? 128 : addrlen; \\\n"
	if got != want {
		t.Fatalf("dynamicPreludeCode() = %q, want %q", got, want)
	}
}

func TestDynamicPreludeUsesPayloadArgBitsLength(t *testing.T) {
	read := CaptureRead{LenFromArgBits: &ArgBitsLength{Arg: 1, Shift: 16, Mask: 16383, ZeroLen: 128}, Max: 512}
	got := dynamicPreludeCode("ioctl", read)
	want := "\t\t\t\tu32 iosz = (((e)->args[1] >> 16) & 0x3fff); \\\n" +
		"\t\t\t\tiosz = (iosz == 0) ? 128 : (iosz > 512 ? 512 : iosz); \\\n"
	if got != want {
		t.Fatalf("dynamicPreludeCode() = %q, want %q", got, want)
	}
}

func TestCaptureSizeExprUsesPayloadRetCountLength(t *testing.T) {
	read := CaptureRead{Arg: 1, CountFromRet: true, ElemSize: 12, Max: 512}
	got := captureSizeExpr("epoll_wait", "exit", read)
	want := "((e)->ret > 0 ? ((e)->ret * 12 > 512 ? 512 : (e)->ret * 12) : 0)"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
	}
}
