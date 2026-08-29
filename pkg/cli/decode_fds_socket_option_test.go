package cli

import "testing"

func TestParseDecodeFDsSocket(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=socket", "/bin/true"})
	if !opts.ShowPaths || opts.ShowPathsMode != DecodeFDModeSocket {
		t.Fatalf("socket details = enabled:%v mode:%d", opts.ShowPaths, opts.ShowPathsMode)
	}
	if !opts.ShowFDSocketValue() || opts.ShowFDPathValue() || opts.ShowFDDeviceValue() {
		t.Fatalf("socket detail selection = path:%v dev:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDDeviceValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDsSocketAndDeviceSet(t *testing.T) {
	opts := ParseArgs([]string{"-e", "decode-fds=socket,dev", "/bin/true"})
	if !opts.ShowFDSocketValue() || !opts.ShowFDDeviceValue() || opts.ShowFDPathValue() {
		t.Fatalf("combined detail selection = path:%v dev:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDDeviceValue(), opts.ShowFDSocketValue())
	}
}

func TestParseDecodeFDsComplementExcludesSocket(t *testing.T) {
	opts := ParseArgs([]string{"--decode-fds=!socket", "/bin/true"})
	if opts.ShowFDSocketValue() || !opts.ShowFDPathValue() || !opts.ShowFDDeviceValue() {
		t.Fatalf("complement detail selection = path:%v dev:%v socket:%v",
			opts.ShowFDPathValue(), opts.ShowFDDeviceValue(), opts.ShowFDSocketValue())
	}
}
