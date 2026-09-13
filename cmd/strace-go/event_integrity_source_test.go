package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestIntegrityEveryReservationConsumesSequenceBeforeReserve(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRootForTest(t), "bpf", "*.h"))
	if err != nil {
		t.Fatal(err)
	}
	reserve := regexp.MustCompile(`(?m)^.*= bpf_ringbuf_reserve(?:_dynptr)?\(`)
	for _, path := range files {
		if filepath.Base(path) == "vmlinux.h" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		for _, index := range reserve.FindAllStringIndex(source, -1) {
			before := source[:index[0]]
			if !strings.HasSuffix(before, "    u64 sequence = next_event_sequence();\n") {
				t.Errorf("%s: reservation lacks an explicit pre-reserve attempt number", filepath.Base(path))
			}
		}
	}
}
