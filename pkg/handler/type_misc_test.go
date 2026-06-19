package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func utsnameBytes(fields ...string) []byte {
	data := make([]byte, 65*6)
	for i, field := range fields {
		if i >= 6 {
			break
		}
		copy(data[i*65:(i+1)*65], field)
	}
	return data
}

func TestDecodeUtsnameVerboseAndAbbrev(t *testing.T) {
	data := utsnameBytes("Linux", "penguin", "7.0.0-22-generic", "#22-Ubuntu SMP", "x86_64", "(none)")
	ctx := &Context{
		Pid:       101,
		Tid:       101,
		TargetPid: 101,
		Ret:       0,
		Args:      [6]uint64{0x1000},
		ScMeta: meta.Syscall{
			Name:     "uname",
			Args:     []string{"name"},
			ArgTypes: []string{"struct utsname *"},
		},
		ProbeRetExit: 0,
		StrArgBuf:    make([]byte, BpfExitArgOffset+65*6),
		MemReader:    mapMemoryReader{},
		Opts:         &cli.Options{Verbose: true},
	}
	copy(ctx.StrArgBuf[BpfExitArgOffset:], data)
	ctx.Decoder = event.NewDecoder(ctx.MemReader)

	got, ok := decodeUtsname(ctx, 0, "struct utsname *", 0x1000)
	want := `{sysname="Linux", nodename="penguin", release="7.0.0-22-generic", version="#22-Ubuntu SMP", machine="x86_64", domainname="(none)"}`
	if !ok || got != want {
		t.Fatalf("decodeUtsname verbose = %q, %v; want %q", got, ok, want)
	}

	ctx.Opts.Verbose = false
	got, ok = decodeUtsname(ctx, 0, "struct utsname *", 0x1000)
	want = `{sysname="Linux", nodename="penguin", ...}`
	if !ok || got != want {
		t.Fatalf("decodeUtsname abbrev = %q, %v; want %q", got, ok, want)
	}
}

func TestFormatRlimitValXlatModes(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		mode string
		want string
	}{
		{name: "infinity abbrev", val: ^uint64(0), mode: "abbrev", want: "RLIM64_INFINITY"},
		{name: "infinity raw", val: ^uint64(0), mode: "raw", want: "18446744073709551615"},
		{name: "infinity verbose", val: ^uint64(0), mode: "verbose", want: "18446744073709551615 /* RLIM64_INFINITY */"},
		{name: "kilobytes abbrev", val: 8192 * 1024, mode: "abbrev", want: "8192*1024"},
		{name: "kilobytes raw", val: 8192 * 1024, mode: "raw", want: "8388608"},
		{name: "kilobytes verbose", val: 8192 * 1024, mode: "verbose", want: "8388608 /* 8192*1024 */"},
		{name: "plain value", val: 123838, mode: "verbose", want: "123838"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatRlimitVal(tt.val, tt.mode); got != tt.want {
				t.Fatalf("formatRlimitVal(%d, %q) = %q, want %q", tt.val, tt.mode, got, tt.want)
			}
		})
	}
}
