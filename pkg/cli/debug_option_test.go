package cli

import "testing"

func TestParseRuntimeDebugAliases(t *testing.T) {
	for _, option := range []string{"-d", "--debug"} {
		opts := ParseArgs([]string{option, "/bin/true"})
		if !opts.RuntimeDebug {
			t.Fatalf("%s did not enable runtime debug", option)
		}
	}
}
