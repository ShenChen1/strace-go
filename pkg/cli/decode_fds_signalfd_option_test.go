package cli

import "testing"

func TestParseDecodeFDsSignalFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=signalfd", "/bin/true"})
	if !opts.ShowPaths || opts.ShowPathsMode != DecodeFDModeSelected {
		t.Fatalf("signalfd details = enabled:%v mode:%d", opts.ShowPaths, opts.ShowPathsMode)
	}
	if !opts.ShowFDSignalFDValue() || opts.ShowFDPathValue() || opts.ShowFDSocketValue() {
		t.Fatalf("signalfd detail selection = path:%v signalfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDSignalFDValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDsComplementExcludesSignalFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=!signalfd", "/bin/true"})
	if opts.ShowFDSignalFDValue() || !opts.ShowFDPathValue() || !opts.ShowFDSocketValue() {
		t.Fatalf("complement detail selection = path:%v signalfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDSignalFDValue(), opts.ShowFDSocketValue())
	}
}
