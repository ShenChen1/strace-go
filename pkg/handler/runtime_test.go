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
