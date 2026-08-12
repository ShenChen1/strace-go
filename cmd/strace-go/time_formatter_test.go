package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestTimeFormatterRelativePrefixClampsOutOfOrderEvent(t *testing.T) {
	formatter := newTimeFormatter(0)
	opts := &cli.Options{PrintRelativeTime: true}

	formatter.Prefix(2_000_000_000, opts)
	if got := formatter.Prefix(1_000_000_000, opts); got != "     0.000000 " {
		t.Fatalf("out-of-order relative prefix = %q, want zero delta", got)
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

func TestTimeFormatterNowMonoNsRoundTripsToWallClock(t *testing.T) {
	formatter := newTimeFormatter(calculateTimeOffset())
	now := time.Now()
	prefix := formatter.Prefix(formatter.NowMonoNs(), &cli.Options{PrintTimeMode: 3})
	// PrintTimeMode 3 renders <epoch-seconds>.<usec>; the round trip must be
	// within a second of the wall clock.
	parts := strings.Split(strings.TrimSpace(prefix), ".")
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		t.Fatalf("parse epoch seconds %q: %v", parts[0], err)
	}
	got := time.Unix(sec, 0)
	if diff := now.Sub(got); diff > time.Second || diff < -time.Second {
		t.Fatalf("NowMonoNs round trip = %v, wall clock = %v (diff %v)", got, now, diff)
	}
}

func TestTimeFormatterNowMonoNsUsesInjectedClock(t *testing.T) {
	clock := &fakeTraceClock{now: time.Unix(300, 0), monoNs: 123456789}
	formatter := newTimeFormatterWithClock(2_000_000_000, clock)

	if got := formatter.NowMonoNs(); got != clock.monoNs {
		t.Fatalf("NowMonoNs() = %d, want injected monotonic time %d", got, clock.monoNs)
	}
}
