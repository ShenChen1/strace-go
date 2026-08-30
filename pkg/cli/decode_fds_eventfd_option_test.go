package cli

import "testing"

func TestParseDecodeFDsEventFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=eventfd", "/bin/true"})
	if !opts.ShowPaths || opts.ShowPathsMode != DecodeFDModeSelected {
		t.Fatalf("eventfd details = enabled:%v mode:%d", opts.ShowPaths, opts.ShowPathsMode)
	}
	if !opts.ShowFDEventFDValue() || opts.ShowFDPathValue() || opts.ShowFDSocketValue() {
		t.Fatalf("eventfd detail selection = path:%v eventfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDEventFDValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDsEventFDAndPathSet(t *testing.T) {
	opts := ParseArgs([]string{"-e", "decode-fds=eventfd,path", "/bin/true"})
	if !opts.ShowFDEventFDValue() || !opts.ShowFDPathValue() || opts.ShowFDSocketValue() {
		t.Fatalf("combined detail selection = path:%v eventfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDEventFDValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDsComplementExcludesEventFD(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=!eventfd", "/bin/true"})
	if opts.ShowFDEventFDValue() || !opts.ShowFDPathValue() || !opts.ShowFDSocketValue() {
		t.Fatalf("complement detail selection = path:%v eventfd:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDEventFDValue(), opts.ShowFDSocketValue())
	}
}
