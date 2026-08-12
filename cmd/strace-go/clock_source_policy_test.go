package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestTimeOffsetSourceUsesInjectedClock(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/main.go"))
	for _, forbidden := range []string{
		"func calculateTimeOffset()",
		"clock = systemTraceClock{}",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("time offset source contains implicit clock owner %q", forbidden)
		}
	}
	if !strings.Contains(source, "func calculateTimeOffsetWithClock(clock traceClock)") {
		t.Fatal("time offset helper must accept an injected trace clock")
	}
}

func TestCalculateTimeOffsetWithoutClockIsZero(t *testing.T) {
	if got := calculateTimeOffsetWithClock(nil); got != 0 {
		t.Fatalf("nil clock offset = %d, want zero", got)
	}
}

func TestRunTraceSessionRejectsNilClockBeforeBootstrap(t *testing.T) {
	err := runTraceSession(&cli.Options{}, nil)
	if err == nil || !strings.Contains(err.Error(), "trace clock is nil") {
		t.Fatalf("runTraceSession() error = %v, want early nil clock error", err)
	}
}
