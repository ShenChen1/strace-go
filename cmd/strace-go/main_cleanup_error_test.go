package main

import (
	"errors"
	"testing"
)

func TestJoinTraceRunErrorPreservesPrimaryAndCleanup(t *testing.T) {
	primary := errors.New("primary failure")
	cleanup := errors.New("cleanup failure")

	joined := joinTraceRunError(primary, cleanup)
	if !errors.Is(joined, primary) || !errors.Is(joined, cleanup) {
		t.Fatalf("joined error = %v, want both primary and cleanup errors", joined)
	}
}

func TestJoinTraceRunErrorReturnsNilForNoErrors(t *testing.T) {
	if err := joinTraceRunError(nil, nil); err != nil {
		t.Fatalf("joinTraceRunError(nil, nil) = %v, want nil", err)
	}
}
