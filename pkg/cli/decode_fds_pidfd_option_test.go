package cli

import "testing"

func TestParseDecodeFDsPIDFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=pidfd", "/bin/true"})
	if !opts.ShowPaths || opts.ShowPathsMode != DecodeFDModeSelected {
		t.Fatalf("pidfd details = enabled:%v mode:%d", opts.ShowPaths, opts.ShowPathsMode)
	}
	if !opts.ShowFDPIDFDValue() || opts.ShowFDPathValue() || opts.ShowFDSocketValue() {
		t.Fatalf("pidfd detail selection = path:%v pidfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDPIDFDValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDAliasPIDFD(t *testing.T) {
	opts := ParseArgs([]string{"-e", "decode-fd=pidfd", "/bin/true"})
	if !opts.ShowFDPIDFDValue() || opts.ShowFDPathValue() {
		t.Fatalf("decode-fd alias selection = path:%v pidfd:%v",
			opts.ShowFDPathValue(), opts.ShowFDPIDFDValue())
	}
}

func TestParseDecodeFDsComplementExcludesPIDFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=!pidfd", "/bin/true"})
	if opts.ShowFDPIDFDValue() || !opts.ShowFDPathValue() || !opts.ShowFDSocketValue() {
		t.Fatalf("complement detail selection = path:%v pidfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDPIDFDValue(), opts.ShowFDSocketValue())
	}
}
