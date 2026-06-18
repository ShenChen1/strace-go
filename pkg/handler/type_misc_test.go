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
