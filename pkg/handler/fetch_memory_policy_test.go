package handler

import (
	"bytes"
	"errors"
	"testing"

	"strace-go/pkg/event"
)

type fetchPolicyMemoryReader struct {
	data  []byte
	reads int
}

func (r *fetchPolicyMemoryReader) Read(int, uint64, int) ([]byte, error) {
	r.reads++
	if r.data == nil {
		return nil, errors.New("unreadable address")
	}
	return append([]byte(nil), r.data...), nil
}

func (r *fetchPolicyMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func TestFetchStructDataUsesSnapshotWithoutMemoryFallback(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{9, 9, 9, 9}}
	decoder := event.NewDecoder()
	ctx := &Context{
		Tid:           1234,
		ProbeRetEnter: 0,
		Decoder:       decoder,
	}

	got, ok := ctx.FetchStructData(0x1000, 4, false, []byte{1, 2, 3, 4})
	if !ok {
		t.Fatal("FetchStructData did not use BPF snapshot")
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("FetchStructData() = %v", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFetchStructDataDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{9, 9, 9, 9}}
	decoder := event.NewDecoder()
	ctx := &Context{
		Tid:           1234,
		ProbeRetEnter: -1,
		Decoder:       decoder,
	}

	if got, ok := ctx.FetchStructData(0x1000, 4, false, nil); ok {
		t.Fatalf("FetchStructData() = %v, want no data", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFetchArgStructDataDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{9, 9, 9, 9}}
	decoder := event.NewDecoder()
	ctx := &Context{
		Tid:           1234,
		ProbeRetEnter: -1,
		Decoder:       decoder,
	}

	if got, ok := ctx.FetchArgStructData(2, 0x1000, 4, false, nil); ok {
		t.Fatalf("FetchArgStructData() = %v, want no data", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestFetchStructDataDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: []byte{9, 9, 9, 9}}
	ctx := &Context{
		Tid:           1234,
		ProbeRetEnter: -1,
		Decoder:       event.NewDecoder(),
	}

	if got, ok := ctx.FetchStructData(0x1000, 4, false, nil); ok {
		t.Fatalf("FetchStructData() = %v, want no data", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
