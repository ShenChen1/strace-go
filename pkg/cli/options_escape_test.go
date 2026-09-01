package cli

import "testing"

func TestParseStringsInHexNonASCIIChars(t *testing.T) {
	opts := ParseArgs([]string{"--strings-in-hex=non-ascii-chars", "/bin/true"})

	if opts.HexEscapeMode != hexEscapeModeNonASCIIChars {
		t.Fatalf("HexEscapeMode = %d, want selective character escaping", opts.HexEscapeMode)
	}
}

func TestParseStringsInHexBareMeansAll(t *testing.T) {
	opts := ParseArgs([]string{"--strings-in-hex", "/bin/true"})

	if opts.HexEscapeMode != 2 {
		t.Fatalf("HexEscapeMode = %d, want all-string hex mode", opts.HexEscapeMode)
	}
}

func TestParseStringsInHexNone(t *testing.T) {
	opts := ParseArgs([]string{"--strings-in-hex=none", "/bin/true"})

	if opts.HexEscapeMode != 0 {
		t.Fatalf("HexEscapeMode = %d, want default escaping mode", opts.HexEscapeMode)
	}
}
