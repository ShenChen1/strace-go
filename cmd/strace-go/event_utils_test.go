package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func testOptions() *cli.Options {
	return &cli.Options{
		TraceSyscalls: make(map[string]bool),
		TracePaths:    make(map[string]bool),
		TraceFDs:      make(map[int32]bool),
		TraceReadFDs:  make(map[int32]bool),
		TraceWriteFDs: make(map[int32]bool),
	}
}

func rawFD(fd int32) uint64 {
	return uint64(uint32(fd))
}

func TestMatchTraceFDs(t *testing.T) {
	tests := []struct {
		name    string
		fds     []int32
		trace   map[int32]bool
		negated bool
		want    bool
	}{
		{name: "positive match", fds: []int32{0}, trace: map[int32]bool{0: true, 9: true}, want: true},
		{name: "positive miss", fds: []int32{3}, trace: map[int32]bool{0: true, 9: true}, want: false},
		{name: "invalid fd excluded", fds: []int32{-1}, trace: map[int32]bool{9: true}, want: false},
		{name: "negated excludes listed fd", fds: []int32{9}, trace: map[int32]bool{9: true}, negated: true, want: false},
		{name: "negated includes other fd", fds: []int32{3}, trace: map[int32]bool{9: true}, negated: true, want: true},
		{name: "negated includes syscall with other fd", fds: []int32{9, 4}, trace: map[int32]bool{9: true}, negated: true, want: true},
		{name: "negated still excludes invalid fd", fds: []int32{-1}, trace: map[int32]bool{9: true}, negated: true, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := testOptions()
			opts.TraceFDs = test.trace
			opts.TraceFDsNegated = test.negated
			if got := matchTraceFDs(test.fds, opts); got != test.want {
				t.Fatalf("matchTraceFDs(%v) = %v, want %v", test.fds, got, test.want)
			}
		})
	}
}

func TestCheckShouldPrintTraceFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[0] = true
	sc := meta.Syscall{Name: "dup", Args: []string{"fd"}}

	if checkShouldPrint(&bpfEvent{Args: [6]uint64{rawFD(-1)}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(-1) should be filtered by --trace-fds=0")
	}
	if !checkShouldPrint(&bpfEvent{Args: [6]uint64{0}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(0) should match --trace-fds=0")
	}
	if checkShouldPrint(&bpfEvent{Args: [6]uint64{3}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(3) should be filtered by --trace-fds=0")
	}
}

func TestCheckShouldPrintTraceFDsNegated(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[9] = true
	opts.TraceFDsNegated = true
	sc := meta.Syscall{Name: "dup", Args: []string{"fd"}}

	if !checkShouldPrint(&bpfEvent{Args: [6]uint64{3}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(3) should match --trace-fds=!9")
	}
	if checkShouldPrint(&bpfEvent{Args: [6]uint64{9}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(9) should be filtered by --trace-fds=!9")
	}
	if checkShouldPrint(&bpfEvent{Args: [6]uint64{rawFD(-1)}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup(-1) should be filtered by --trace-fds=!9")
	}

	sc = meta.Syscall{Name: "dup2", Args: []string{"oldfd", "newfd"}}
	opts.TraceSyscalls["dup2"] = true
	if !checkShouldPrint(&bpfEvent{Args: [6]uint64{9, 4}}, sc, "", false, 101, opts, nil) {
		t.Fatal("dup2(9, 4) should match --trace-fds=!9 because fd 4 is not excluded")
	}
}

func TestCheckShouldPrintTraceFDsOrPath(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[0] = true
	opts.TracePaths["/dev/full"] = true
	sc := meta.Syscall{Name: "dup", Args: []string{"fd"}}
	fdMap := map[string]string{"101:9": "/dev/full"}

	if !checkShouldPrint(&bpfEvent{Args: [6]uint64{0}}, sc, "", false, 101, opts, fdMap) {
		t.Fatal("dup(0) should match --trace-fds=0 even with -P")
	}
	if !checkShouldPrint(&bpfEvent{Args: [6]uint64{9}}, sc, "", false, 101, opts, fdMap) {
		t.Fatal("dup(9) should match -P /dev/full even with --trace-fds=0")
	}
	if checkShouldPrint(&bpfEvent{Args: [6]uint64{3}}, sc, "", false, 101, opts, fdMap) {
		t.Fatal("dup(3) should not match --trace-fds=0 or -P /dev/full")
	}
}

func TestDup2FormatsArgsBeforeFDMapUpdateAndReturnAfter(t *testing.T) {
	fdMap := map[string]string{
		"101:3": "/dev/null",
		"101:4": "/dev/full",
	}
	sc := meta.Syscall{
		Name:     "dup2",
		Args:     []string{"oldfd", "newfd"},
		ArgTypes: []string{"unsigned int", "unsigned int"},
	}
	eventRaw := &bpfEvent{
		Pid:  101,
		Tid:  101,
		Args: [6]uint64{3, 4},
		Ret:  4,
	}
	ctx := &handler.Context{
		Pid:       101,
		TargetPid: 101,
		Args:      eventRaw.Args,
		Ret:       eventRaw.Ret,
		ScMeta:    sc,
		Opts: &cli.Options{
			ShowPaths:     true,
			ShowPathsMode: 1,
		},
		FdMap: fdMap,
	}

	res := handler.Get("dup2").Handle(ctx)
	if got, want := res.ArgParts, []string{"3</dev/null>", "4</dev/full>"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dup2 args = %#v, want %#v", got, want)
	}

	updateFDMap(eventRaw, sc, "", nil, 101, fdMap)
	if got := formatSyscallRet("dup2", 4, res, ctx); got != "4</dev/null>" {
		t.Fatalf("dup2 return = %q, want %q", got, "4</dev/null>")
	}
}
