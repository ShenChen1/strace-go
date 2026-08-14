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

func TestCloseNamedBPFResourcesParallelRecordsStableResourceTimings(t *testing.T) {
	observer := &recordingTraceCleanupObserver{}
	resources := []traceBPFResource{
		{Name: "handler_collection", Closer: &immediateBPFCloser{}},
		{Name: "core_objects", Closer: &immediateBPFCloser{}},
	}

	err := closeNamedBPFResourcesParallel(
		resources,
		&fakeTraceClock{monoNs: 101},
		observer,
	)
	if err != nil {
		t.Fatalf("closeNamedBPFResourcesParallel() error = %v, want nil", err)
	}
	if len(observer.steps) != 2 || observer.steps[0].Name != "handler_collection" ||
		observer.steps[1].Name != "core_objects" {
		t.Fatalf("resource timings = %+v, want input order", observer.steps)
	}
}

func TestTracepointLinkCloserAddsLinkIndexToError(t *testing.T) {
	wantErr := errors.New("link close failed")
	closer := tracepointLinkCloser{
		index: 4,
		closer: &immediateBPFCloser{
			err: wantErr,
		},
	}

	err := closer.Close()
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "BPF link 4") {
		t.Fatalf("tracepoint link close error = %v, want index and cause", err)
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
