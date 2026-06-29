package main

import "testing"

func TestDynamicSizeStrKeepsDefaultExitSize(t *testing.T) {
	got := dynamicSizeStr("unknown", "exit", CaptureRead{Arg: 1})
	want := "((e)->ret > 0 ? ((e)->ret * 32 > 512 ? 512 : (e)->ret * 32) : 0)"
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

func TestCaptureSizeExprUsesPayloadCountLength(t *testing.T) {
	countArg := 2
	read := CaptureRead{Arg: 1, CountFromArg: &countArg, ElemSize: 16, Max: 512}
	got := captureSizeExpr("readv", "enter", read)
	want := "((e)->args[2] > 0 ? ((e)->args[2] * 16 > 512 ? 512 : (e)->args[2] * 16) : 0)"
	if got != want {
		t.Fatalf("captureSizeExpr() = %q, want %q", got, want)
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
