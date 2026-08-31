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

func TestParseDecodePIDsPIDNSAliases(t *testing.T) {
	for _, args := range [][]string{
		{"--decode-pids=pidns", "/bin/true"},
		{"--decode-pid", "pidns", "/bin/true"},
		{"-e", "decode-pid=pidns", "/bin/true"},
		{"--pidns-translation", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.DecodePIDsPIDNS || opts.DecodePIDsComm {
			t.Fatalf("ParseArgs(%v) decode-pids = comm:%v pidns:%v, want pidns only",
				args, opts.DecodePIDsComm, opts.DecodePIDsPIDNS)
		}
	}
}

func TestParseDecodePIDsSetSemanticsAndOptionOrder(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantComm  bool
		wantPIDNS bool
	}{
		{name: "both", args: []string{"--decode-pids=pidns,comm", "/bin/true"}, wantComm: true, wantPIDNS: true},
		{name: "all", args: []string{"--decode-pids=all", "/bin/true"}, wantComm: true, wantPIDNS: true},
		{name: "complement comm", args: []string{"--decode-pids=!comm", "/bin/true"}, wantPIDNS: true},
		{name: "complement both", args: []string{"--decode-pids=!comm,pidns", "/bin/true"}},
		{name: "short option resets", args: []string{"--decode-pids=pidns", "-Y", "/bin/true"}, wantComm: true},
		{name: "later set resets", args: []string{"-Y", "--decode-pids=pidns", "/bin/true"}, wantPIDNS: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := ParseArgs(tt.args)
			if opts.DecodePIDsComm != tt.wantComm || opts.DecodePIDsPIDNS != tt.wantPIDNS {
				t.Fatalf("decode-pids = comm:%v pidns:%v, want comm:%v pidns:%v",
					opts.DecodePIDsComm, opts.DecodePIDsPIDNS, tt.wantComm, tt.wantPIDNS)
			}
		})
	}
}
