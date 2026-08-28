package cli

import "testing"

func TestParseStringsInHexNonASCIIChars(t *testing.T) {
	opts := ParseArgs([]string{"--strings-in-hex=non-ascii-chars", "/bin/true"})

	if opts.HexEscapeMode != hexEscapeModeNonASCIIChars {
		t.Fatalf("HexEscapeMode = %d, want selective character escaping", opts.HexEscapeMode)
	}
}
