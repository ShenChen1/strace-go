package cli

import "testing"

func TestOptionsReadOnlyViewIsNilSafe(t *testing.T) {
	var opts *Options
	if opts.StringLimitValue() != 0 || opts.HexEscapeModeValue() != 0 || opts.ShowPathsModeValue() != 0 {
		t.Fatal("nil options view returned a non-zero scalar")
	}
	if opts.VerboseValue() || opts.VerboseDisabledFor("read") || opts.ShowPathsValue() {
		t.Fatal("nil options view enabled a boolean capability")
	}
	if opts.TraceReadFD(0) || opts.TraceWriteFD(1) {
		t.Fatal("nil options view traced a file descriptor")
	}
}

func TestOptionsReadOnlyViewReflectsConfiguredValues(t *testing.T) {
	opts := &Options{
		StringLimit:     17,
		HexEscapeMode:   2,
		Verbose:         true,
		VerboseDisabled: map[string]bool{"read": true},
		ShowPaths:       true,
		ShowPathsMode:   2,
		TraceReadFDs:    map[int32]bool{0: true},
		TraceWriteFDs:   map[int32]bool{1: true},
	}

	if got := opts.StringLimitValue(); got != 17 {
		t.Fatalf("StringLimitValue() = %d, want 17", got)
	}
	if got := opts.HexEscapeModeValue(); got != 2 {
		t.Fatalf("HexEscapeModeValue() = %d, want 2", got)
	}
	if !opts.VerboseValue() || !opts.VerboseDisabledFor("read") {
		t.Fatal("configured verbose capabilities were not exposed")
	}
	if !opts.ShowPathsValue() || opts.ShowPathsModeValue() != 2 {
		t.Fatal("configured path capabilities were not exposed")
	}
	if !opts.TraceReadFD(0) || opts.TraceReadFD(1) || !opts.TraceWriteFD(1) || opts.TraceWriteFD(0) {
		t.Fatal("configured fd capabilities were not exposed")
	}
}
