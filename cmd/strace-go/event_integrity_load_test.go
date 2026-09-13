package main

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestIntegrityBPFHandlerLoad(t *testing.T) {
	if os.Getenv("STRACE_GO_TEST_INTEGRITY_BPF") != "1" {
		t.Skip("set STRACE_GO_TEST_INTEGRITY_BPF=1 for kernel handler load tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"path", loadBpfEnterPath},
		{"control", loadBpfEnterControl},
		{"structured", loadBpfEnterStructured},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec, err := test.load()
			if err != nil {
				t.Fatal(err)
			}
			collection, err := ebpf.NewCollection(spec)
			if err != nil {
				var verifier *ebpf.VerifierError
				if errors.As(err, &verifier) {
					t.Fatalf("%+v", verifier)
				}
				t.Fatal(err)
			}
			collection.Close()
		})
	}
}
