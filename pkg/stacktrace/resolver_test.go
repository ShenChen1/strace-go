package stacktrace

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestResolverResolvesMappedFile(t *testing.T) {
	resolver := NewResolver(os.Getpid())
	if len(resolver.regions) == 0 {
		t.Fatal("expected the current process to have file-backed mappings")
	}

	region := resolver.regions[0]
	got := resolver.Resolve(region.Start)
	if !strings.Contains(got, region.Path) {
		t.Fatalf("Resolve(%#x) = %q, want mapped path %q", region.Start, got, region.Path)
	}
}

func TestResolverUnknownAddressFallsBackToPointer(t *testing.T) {
	const ip = uint64(0x1234)

	resolver := NewResolver(-1)
	got := resolver.Resolve(ip)
	want := fmt.Sprintf("[0x%x]", ip)
	if got != want {
		t.Fatalf("Resolve(%#x) = %q, want %q", ip, got, want)
	}
}
