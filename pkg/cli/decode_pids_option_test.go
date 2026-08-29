package cli

import "testing"

func TestParseDecodePIDsCommAliases(t *testing.T) {
	for _, args := range [][]string{
		{"-Y", "/bin/true"},
		{"--decode-pids=comm", "/bin/true"},
		{"-e", "decode-pids=comm", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.DecodePIDsComm {
			t.Fatalf("ParseArgs(%v) did not enable comm decoding", args)
		}
	}
}

func TestParseDecodePIDsNoneDisablesComm(t *testing.T) {
	opts := ParseArgs([]string{"-Y", "--decode-pids=none", "/bin/true"})
	if opts.DecodePIDsComm {
		t.Fatal("decode-pids=none left comm decoding enabled")
	}
}
