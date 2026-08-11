package stacktrace

import (
	"fmt"
	"testing"
)

func TestResolverFormatsRawAddress(t *testing.T) {
	resolver := NewResolver()
	const ip = uint64(0x1234)

	got := resolver.Resolve(ip)
	want := fmt.Sprintf("[0x%x]", ip)
	if got != want {
		t.Fatalf("Resolve(%#x) = %q, want %q", ip, got, want)
	}
}

func TestResolverKeepsAddressStableAcrossCalls(t *testing.T) {
	resolver := NewResolver()
	const ip = uint64(0x7fff00001234)

	first := resolver.Resolve(ip)
	second := resolver.Resolve(ip)
	if first != second {
		t.Fatalf("Resolve(%#x) changed from %q to %q", ip, first, second)
	}

	got := resolver.Resolve(ip)
	want := fmt.Sprintf("[0x%x]", ip)
	if got != want {
		t.Fatalf("Resolve(%#x) = %q, want %q", ip, got, want)
	}
}
