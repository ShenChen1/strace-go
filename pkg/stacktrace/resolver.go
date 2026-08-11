package stacktrace

import "fmt"

type Resolver struct {
}

// NewResolver creates the stateless BPF instruction-pointer formatter.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Resolve formats only the instruction pointer captured by BPF at probe time.
// Resolving symbols from a target's live mappings would reintroduce a racing
// process snapshot, so symbol names are intentionally unavailable here.
func (r *Resolver) Resolve(ip uint64) string {
	return fmt.Sprintf("[0x%x]", ip)
}
