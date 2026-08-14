package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type barrierBPFCloser struct {
	started chan<- struct{}
	release <-chan struct{}
	err     error
}

func (c *barrierBPFCloser) Close() error {
	c.started <- struct{}{}
	<-c.release
	return c.err
}

func TestCloseBPFResourcesParallelStartsIndependentClosersTogether(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	resources := []io.Closer{
		&barrierBPFCloser{started: started, release: release},
		&barrierBPFCloser{started: started, release: release},
	}
	done := make(chan error, 1)
	go func() { done <- closeBPFResourcesParallel(resources) }()

	waitForBPFClosers(t, started, 2)
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("closeBPFResourcesParallel() error = %v, want nil", err)
	}
}

func TestCloseBPFResourcesParallelJoinsErrorsInInputOrder(t *testing.T) {
	firstErr := errors.New("first close failed")
	secondErr := errors.New("second close failed")
	resources := []io.Closer{
		&immediateBPFCloser{err: firstErr},
		&immediateBPFCloser{err: secondErr},
	}

	err := closeBPFResourcesParallel(resources)
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("close error = %v, want both resource errors", err)
	}
	if got, want := err.Error(), "first close failed\nsecond close failed"; !strings.Contains(got, want) {
		t.Fatalf("joined close error = %q, want input order %q", got, want)
	}
}

type immediateBPFCloser struct {
	err error
}

func (c *immediateBPFCloser) Close() error {
	return c.err
}

func waitForBPFClosers(t *testing.T, started <-chan struct{}, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	for count := 0; count < want; count++ {
		select {
		case <-started:
		case <-deadline:
			t.Fatalf("only %d of %d BPF closers started", count, want)
		}
	}
}
