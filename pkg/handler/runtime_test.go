package handler

import "testing"

func TestRuntimeStateIsScopedPerSession(t *testing.T) {
	first := NewRuntime()
	second := NewRuntime()

	if got := first.NextFiemapCall(1234); got != 1 {
		t.Fatalf("first runtime call = %d, want 1", got)
	}
	if got := first.NextFiemapCall(1234); got != 2 {
		t.Fatalf("first runtime second call = %d, want 2", got)
	}
	if got := second.NextFiemapCall(1234); got != 1 {
		t.Fatalf("second runtime call = %d, want independent 1", got)
	}
}

func TestRuntimeEventfdFallbackStateIsScoped(t *testing.T) {
	first := NewRuntime()
	second := NewRuntime()
	first.lastEventfdID = 40

	got := first.EventfdInfo(101, 0, 7, 0, true)
	if got != "{eventfd-count=0x7, eventfd-id=41, eventfd-semaphore=0}" {
		t.Fatalf("first eventfd fallback = %q", got)
	}
	if got := second.EventfdInfo(101, 0, 7, 0, true); got != "" {
		t.Fatalf("second eventfd fallback = %q, want empty state", got)
	}
}
