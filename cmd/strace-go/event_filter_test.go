package main

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
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

func viewWithArgs(args [6]uint64) syscallEventView {
	return syscallEventView{valid: true, args: args}
}

func checkShouldPrintForTest(view syscallEventView, sc meta.Syscall, opts *cli.Options, configure func(*printFilterRequest)) bool {
	req := printFilterRequest{
		view:      view,
		scMeta:    sc,
		targetPid: 101,
		opts:      opts,
	}
	if configure != nil {
		configure(&req)
	}
	return checkShouldPrintFromView(req)
}

func filterTestPollfd(fd int32) []byte {
	data := make([]byte, pollPayloadFdSize)
	binary.LittleEndian.PutUint32(data[0:4], uint32(fd))
	return data
}

func filterTestFdSet(fds ...int) []byte {
	data := make([]byte, selectPayloadFdSetSize)
	for _, fd := range fds {
		data[fd/8] |= 1 << uint(fd%8)
	}
	return data
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

	if checkShouldPrintForTest(viewWithArgs([6]uint64{rawFD(-1)}), sc, opts, nil) {
		t.Fatal("dup(-1) should be filtered by --trace-fds=0")
	}
	if !checkShouldPrintForTest(viewWithArgs([6]uint64{0}), sc, opts, nil) {
		t.Fatal("dup(0) should match --trace-fds=0")
	}
	if checkShouldPrintForTest(viewWithArgs([6]uint64{3}), sc, opts, nil) {
		t.Fatal("dup(3) should be filtered by --trace-fds=0")
	}
}

func TestCheckShouldPrintFromViewUsesEventViewFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[5] = true
	sc := meta.Syscall{Name: "dup", Args: []string{"fd"}}

	view := syscallEventView{valid: true, args: [6]uint64{5}}

	if !checkShouldPrintForTest(view, sc, opts, nil) {
		t.Fatal("dup(5) view should match --trace-fds=5")
	}
}

func TestCheckShouldPrintTraceFDsNegated(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[9] = true
	opts.TraceFDsNegated = true
	sc := meta.Syscall{Name: "dup", Args: []string{"fd"}}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{3}), sc, opts, nil) {
		t.Fatal("dup(3) should match --trace-fds=!9")
	}
	if checkShouldPrintForTest(viewWithArgs([6]uint64{9}), sc, opts, nil) {
		t.Fatal("dup(9) should be filtered by --trace-fds=!9")
	}
	if checkShouldPrintForTest(viewWithArgs([6]uint64{rawFD(-1)}), sc, opts, nil) {
		t.Fatal("dup(-1) should be filtered by --trace-fds=!9")
	}

	sc = meta.Syscall{Name: "dup2", Args: []string{"oldfd", "newfd"}}
	opts.TraceSyscalls["dup2"] = true
	if !checkShouldPrintForTest(viewWithArgs([6]uint64{9, 4}), sc, opts, nil) {
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

	withFDMap := func(req *printFilterRequest) { req.fdMap = fdMap }

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{0}), sc, opts, withFDMap) {
		t.Fatal("dup(0) should match --trace-fds=0 even with -P")
	}
	if !checkShouldPrintForTest(viewWithArgs([6]uint64{9}), sc, opts, withFDMap) {
		t.Fatal("dup(9) should match -P /dev/full even with --trace-fds=0")
	}
	if checkShouldPrintForTest(viewWithArgs([6]uint64{3}), sc, opts, withFDMap) {
		t.Fatal("dup(3) should not match --trace-fds=0 or -P /dev/full")
	}
}

func TestCheckShouldPrintTraceFDsUsesPollPayloadFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["poll"] = true
	opts.TraceFDs[9] = true
	sc := meta.Syscall{Name: "poll", Args: []string{"ufds", "nfds", "timeout"}}
	sections := []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data:      append(filterTestPollfd(4), filterTestPollfd(9)...),
		},
	}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{0x1000, 2, 0}), sc, opts, func(req *printFilterRequest) {
		req.payloadSections = sections
	}) {
		t.Fatal("poll payload fd 9 should match --trace-fds=9")
	}
}

func TestCheckShouldPrintTracePathUsesPollPayloadFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["ppoll"] = true
	opts.TracePaths["/dev/full"] = true
	sc := meta.Syscall{Name: "ppoll", Args: []string{"ufds", "nfds", "tsp", "sigmask", "sigsetsize"}}
	fdMap := map[string]string{"101:9": "/dev/full"}
	sections := []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindStruct,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  0,
			ProbeRet:  0,
			Data:      append(filterTestPollfd(4), filterTestPollfd(9)...),
		},
	}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{0x1000, 2, 0, 0, 8}), sc, opts, func(req *printFilterRequest) {
		req.fdMap = fdMap
		req.payloadSections = sections
	}) {
		t.Fatal("ppoll payload fd 9 should match -P /dev/full")
	}
}

func TestCheckShouldPrintTraceFDsUsesSelectPayloadFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["select"] = true
	opts.TraceFDs[9] = true
	sc := meta.Syscall{Name: "select", Args: []string{"nfds", "readfds", "writefds", "exceptfds", "timeout"}}
	sections := []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      filterTestFdSet(4, 9),
		},
	}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{10, 0x1000, 0, 0, 0}), sc, opts, func(req *printFilterRequest) {
		req.payloadSections = sections
	}) {
		t.Fatal("select payload fd 9 should match --trace-fds=9")
	}
}

func TestCheckShouldPrintTracePathUsesSelectPayloadFDs(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["_newselect"] = true
	opts.TracePaths["/dev/full"] = true
	sc := meta.Syscall{Name: "_newselect", Args: []string{"nfds", "readfds", "writefds", "exceptfds", "timeout"}}
	fdMap := map[string]string{"101:9": "/dev/full"}
	sections := []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  2,
			ProbeRet:  0,
			Data:      filterTestFdSet(9),
		},
	}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{10, 0, 0x2000, 0, 0}), sc, opts, func(req *printFilterRequest) {
		req.fdMap = fdMap
		req.payloadSections = sections
	}) {
		t.Fatal("_newselect payload fd 9 should match -P /dev/full")
	}
}

func TestCheckShouldPrintTracePathUsesFsconfigAuxFD(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["fsconfig"] = true
	opts.TracePaths["/dev/full"] = true
	sc := meta.Syscall{Name: "fsconfig", Args: []string{"fd", "cmd", "key", "value", "aux"}}
	fdMap := map[string]string{"101:3": "/dev/full"}

	if !checkShouldPrintForTest(viewWithArgs([6]uint64{rawFD(-100), 3, 0, 0, 3}), sc, opts, func(req *printFilterRequest) {
		req.fdMap = fdMap
	}) {
		t.Fatal("fsconfig aux fd 3 should match -P /dev/full")
	}
}

func TestCheckShouldPrintTracePathIgnoresFsconfigContextFD(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["fsconfig"] = true
	opts.TracePaths["/dev/full"] = true
	sc := meta.Syscall{Name: "fsconfig", Args: []string{"fd", "cmd", "key", "value", "aux"}}
	fdMap := map[string]string{"101:3": "/dev/full"}

	if checkShouldPrintForTest(viewWithArgs([6]uint64{3, 0, 0, 0, 0}), sc, opts, func(req *printFilterRequest) {
		req.fdMap = fdMap
	}) {
		t.Fatal("fsconfig context fd should not match -P /dev/full for SET_FLAG")
	}
}

func TestFsconfigPathTextFromPayloadUsesValueSection(t *testing.T) {
	session := &traceSession{decoder: event.NewDecoder()}
	args := [6]uint64{rawFD(-1), 3, 0x1000, 0x2000, rawFD(-100)}
	sections := []handler.PayloadSection{
		{Kind: handler.PayloadKindString, Direction: handler.PayloadDirectionIn, ArgIndex: 3, UserPtr: 0x2000, ProbeRet: 0, Data: []byte("/dev/full\x00")},
	}

	text, ok := pathTextFromPayload(newSyscallEventContextDeps(session), viewWithArgs(args), meta.Syscall{Name: "fsconfig"}, sections)
	if !ok || text != `"/dev/full"` {
		t.Fatalf("fsconfig path text = %q, %v; want value path", text, ok)
	}
}

func TestCheckShouldPrintSelectPayloadFDsIgnoresNegativeNfds(t *testing.T) {
	opts := testOptions()
	opts.TraceSyscalls["select"] = true
	opts.TraceFDs[9] = true
	sc := meta.Syscall{Name: "select", Args: []string{"nfds", "readfds", "writefds", "exceptfds", "timeout"}}
	sections := []handler.PayloadSection{
		{
			Kind:      handler.PayloadKindBytes,
			Direction: handler.PayloadDirectionIn,
			ArgIndex:  1,
			ProbeRet:  0,
			Data:      filterTestFdSet(9),
		},
	}

	if checkShouldPrintForTest(viewWithArgs([6]uint64{0xffffffffffffffff, 0x1000, 0, 0, 0}), sc, opts, func(req *printFilterRequest) {
		req.payloadSections = sections
	}) {
		t.Fatal("select(-1, ...) should not derive fd matches from fd_set payload")
	}
}
