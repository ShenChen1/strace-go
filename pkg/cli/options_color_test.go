package cli

import "testing"

func TestParseColorModes(t *testing.T) {
	for _, mode := range []string{"auto", "always", "never"} {
		opts := ParseArgs([]string{"--color=" + mode, "/bin/true"})
		if opts.ColorMode != mode {
			t.Fatalf("--color=%s parsed mode %q", mode, opts.ColorMode)
		}
	}
}
