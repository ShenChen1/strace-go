package main

import (
	"testing"

	"strace-go/pkg/cli"
)

func TestTimeFormatterRelativePrefixTracksPreviousSyscall(t *testing.T) {
	formatter := newTimeFormatter(0)
	opts := &cli.Options{PrintRelativeTime: true}

	if got := formatter.Prefix(1_000_000_000, opts); got != "     0.000000 " {
		t.Fatalf("first relative prefix = %q", got)
	}
	if got := formatter.Prefix(1_234_567_000, opts); got != "     0.234567 " {
		t.Fatalf("second relative prefix = %q", got)
	}
}

func TestTimeFormatterUnixPrefixUsesBootOffset(t *testing.T) {
	formatter := newTimeFormatter(2_000_000_000)
	opts := &cli.Options{PrintTimeMode: 3}

	if got := formatter.Prefix(1_234_567_000, opts); got != "3.234567 " {
		t.Fatalf("unix prefix = %q", got)
	}
}

func TestTimeFormatterReturnsEmptyWhenDisabled(t *testing.T) {
	formatter := newTimeFormatter(0)

	if got := formatter.Prefix(1_000_000_000, &cli.Options{}); got != "" {
		t.Fatalf("disabled prefix = %q", got)
	}
	if got := formatter.Prefix(1_000_000_000, nil); got != "" {
		t.Fatalf("nil opts prefix = %q", got)
	}
}
