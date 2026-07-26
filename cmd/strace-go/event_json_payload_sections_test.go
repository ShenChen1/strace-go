package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

func TestJSONSyscallEventIncludesOutBufferPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
	}{
		{name: "getcwd", args: [6]uint64{0x3000, 32}, argIndex: 0},
		{name: "readlink", args: [6]uint64{0x2000, 0x3000, 32}, argIndex: 1},
		{name: "readlinkat", args: [6]uint64{^uint64(99), 0x2000, 0x3000, 32}, argIndex: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := []byte("target")
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeExit,
				Args:          tt.args,
				Ret:           6,
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			}
			setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
				kind:    payloadTLVKindBytes,
				flags:   payloadTLVFlagDirectionOut,
				arg:     uint16(tt.argIndex),
				userPtr: tt.args[tt.argIndex],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "bytes" || section.Direction != "out" || section.ArgIndex != tt.argIndex {
				t.Fatalf("%s section metadata = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
				t.Fatalf("%s section data = %q, want target", tt.name, string(got))
			}
		})
	}
}

func TestJSONSyscallEventIncludesStructPayloadSections(t *testing.T) {
	tests := []struct {
		name     string
		args     [6]uint64
		argIndex int
		size     int
		fill     byte
	}{
		{name: "stat", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x11},
		{name: "lstat", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x22},
		{name: "fstat", args: [6]uint64{3, 0x2000}, argIndex: 1, size: statPayloadStructSize, fill: 0x33},
		{name: "newfstatat", args: [6]uint64{^uint64(99), 0x1000, 0x2000}, argIndex: 2, size: statPayloadStructSize, fill: 0x44},
		{name: "statfs", args: [6]uint64{0x1000, 0x2000}, argIndex: 1, size: statfsPayloadStructSize, fill: 0x55},
		{name: "fstatfs", args: [6]uint64{3, 0x2000}, argIndex: 1, size: statfsPayloadStructSize, fill: 0x66},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := bytes.Repeat([]byte{tt.fill}, tt.size)
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeExit,
				Args:          tt.args,
				Ret:           0,
				ProbeRetEnter: -1,
				ProbeRetExit:  0,
			}
			setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   payloadTLVFlagDirectionOut,
				arg:     uint16(tt.argIndex),
				userPtr: tt.args[tt.argIndex],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "struct" || section.Direction != "out" || section.ArgIndex != tt.argIndex {
				t.Fatalf("%s section metadata = %+v", tt.name, section)
			}
			if section.UserLen != uint32(tt.size) || section.CopiedLen != uint32(tt.size) {
				t.Fatalf("%s section bounds = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
				t.Fatalf("%s section data length = %d, want %d", tt.name, len(got), len(wantData))
			}
		})
	}
}

func TestJSONSyscallEventSkipsStructPayloadSectionOnFailedStat(t *testing.T) {
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{3, 0x2000},
		Ret:           -2,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
	}

	scMeta := meta.Syscall{Name: "fstat"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 0 {
		t.Fatalf("PayloadSections = %+v, want none for failed fstat", ev.PayloadSections)
	}
}

func TestJSONSyscallEventIncludesPollStructPayloadSections(t *testing.T) {
	enterData := []byte("pollfd-enter-000")
	exitData := []byte("pollfd-exit--000")
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{0x2000, 2, 1000},
		Ret:           1,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}
	setJSONTestTLVPayload(t, eventRaw,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: eventRaw.Args[0],
			userLen: uint32(len(enterData)),
			data:    enterData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     0,
			userPtr: eventRaw.Args[0],
			userLen: uint32(len(exitData)),
			data:    exitData,
		},
	)

	scMeta := meta.Syscall{Name: "poll"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	enter := ev.PayloadSections[0]
	exit := ev.PayloadSections[1]
	if enter.Kind != "struct" || enter.Direction != "in" || enter.ArgIndex != 0 || enter.UserLen != 16 {
		t.Fatalf("poll enter section = %+v", enter)
	}
	if exit.Kind != "struct" || exit.Direction != "out" || exit.ArgIndex != 0 || exit.UserLen != 16 {
		t.Fatalf("poll exit section = %+v", exit)
	}
	if got := mustDecodeBase64(t, enter.DataBase64); !bytes.Equal(got, enterData) {
		t.Fatalf("poll enter data = %q", string(got))
	}
	if got := mustDecodeBase64(t, exit.DataBase64); !bytes.Equal(got, exitData) {
		t.Fatalf("poll exit data = %q", string(got))
	}
}

func TestJSONSyscallEventIncludesPpollTimeoutPayloadSection(t *testing.T) {
	pollfdsData := []byte("pollfd-i")
	timeoutData := bytes.Repeat([]byte{0x22}, timespecPayloadStructSize)
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 1, 0x3000},
		ProbeRetEnter: 0,
	}
	setJSONTestTLVPayload(t, eventRaw,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: eventRaw.Args[0],
			userLen: uint32(len(pollfdsData)),
			data:    pollfdsData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     2,
			userPtr: eventRaw.Args[2],
			userLen: uint32(len(timeoutData)),
			data:    timeoutData,
		},
	)

	scMeta := meta.Syscall{Name: "ppoll"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	pollfds := ev.PayloadSections[0]
	timeout := ev.PayloadSections[1]
	if pollfds.Kind != "struct" || pollfds.Direction != "in" || pollfds.ArgIndex != 0 || pollfds.UserLen != 8 {
		t.Fatalf("ppoll pollfds section = %+v", pollfds)
	}
	if timeout.Kind != "struct" || timeout.Direction != "in" || timeout.ArgIndex != 2 || timeout.UserLen != 16 {
		t.Fatalf("ppoll timeout section = %+v", timeout)
	}
}

func TestJSONSyscallEventIncludesEpollCtlStructPayloadSection(t *testing.T) {
	assertJSONEpollStructPayloadSections(t, "epoll_ctl", bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{5, 1, 6, 0x3000},
		ProbeRetEnter: 0,
	}, 1, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     3,
		userPtr: 0x3000,
		userLen: epollPayloadEventSize,
		data:    bytes.Repeat([]byte{0x11}, epollPayloadEventSize),
	})
}

func TestJSONSyscallEventIncludesEpollWaitStructPayloadSection(t *testing.T) {
	assertJSONEpollStructPayloadSections(t, "epoll_wait", bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{5, 0x2000, 2, 1000},
		Ret:           2,
		ProbeRetEnter: -1,
		ProbeRetExit:  0,
	}, 1, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 24,
		data:    bytes.Repeat([]byte{0x33}, 24),
	})
}

func TestJSONSyscallEventIncludesEpollPwait2StructPayloadSections(t *testing.T) {
	assertJSONEpollStructPayloadSections(t, "epoll_pwait2", bpfEvent{
		EventType:     bpfEventTypeExit,
		Args:          [6]uint64{5, 0x2000, 2, 0x3000, 0, 8},
		Ret:           2,
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
	}, 2,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     3,
			userPtr: 0x3000,
			userLen: timespecPayloadStructSize,
			data:    bytes.Repeat([]byte{0x22}, timespecPayloadStructSize),
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     1,
			userPtr: 0x2000,
			userLen: 24,
			data:    bytes.Repeat([]byte{0x33}, 24),
		},
	)
}

func assertJSONEpollStructPayloadSections(
	t *testing.T,
	name string,
	eventRaw bpfEvent,
	wantCount int,
	sections ...payloadTLVTestSection,
) {
	t.Helper()
	setJSONTestTLVPayload(t, &eventRaw, sections...)
	scMeta := meta.Syscall{Name: name}
	ev := newJSONSyscallEvent(&eventRaw, scMeta, payloadSectionsForEvent(&eventRaw, scMeta))
	if len(ev.PayloadSections) != wantCount {
		t.Fatalf("PayloadSections = %d, want %d", len(ev.PayloadSections), wantCount)
	}
	for _, section := range ev.PayloadSections {
		if section.Kind != "struct" {
			t.Fatalf("%s section kind = %+v", name, section)
		}
	}
}

func TestJSONSyscallEventIncludesIovecPayloadSection(t *testing.T) {
	tests := []struct {
		name string
		args [6]uint64
	}{
		{name: "readv", args: [6]uint64{3, 0x3000, 1}},
		{name: "process_madvise", args: [6]uint64{9, 0x3000, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantData := []byte("0123456789abcdef")
			eventRaw := &bpfEvent{
				Pid:           101,
				Tid:           101,
				EventVersion:  2,
				EventType:     bpfEventTypeEnter,
				Args:          tt.args,
				ProbeRetEnter: 0,
			}
			setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
				kind:    payloadTLVKindIovec,
				arg:     1,
				userPtr: tt.args[1],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			scMeta := meta.Syscall{Name: tt.name}
			ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
			if len(ev.PayloadSections) != 1 {
				t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
			}
			section := ev.PayloadSections[0]
			if section.Kind != "iovec" || section.Direction != "in" || section.ArgIndex != 1 || section.UserLen != 16 {
				t.Fatalf("%s iovec section metadata = %+v", tt.name, section)
			}
			if got := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(got, wantData) {
				t.Fatalf("%s iovec data = %q, want captured iovec bytes", tt.name, string(got))
			}
		})
	}
}

func TestJSONSyscallEventIncludesMemfdNamePayloadSection(t *testing.T) {
	nameData := []byte("memfd-name\x00")
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 0},
		ProbeRetEnter: 0,
	}
	setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: eventRaw.Args[0],
		userLen: uint32(len(nameData)),
		data:    nameData,
	})

	scMeta := meta.Syscall{Name: "memfd_create"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "string" || section.Direction != "in" || section.ArgIndex != 0 || section.UserPtr != 0x2000 {
		t.Fatalf("memfd_create section metadata = %+v", section)
	}
	if section.UserLen != uint32(len(nameData)) || section.CopiedLen != uint32(len(nameData)) {
		t.Fatalf("memfd_create section bounds = %+v", section)
	}
	if got := mustDecodeBase64(t, section.DataBase64); string(got) != "memfd-name\x00" {
		t.Fatalf("memfd_create section data = %q, want memfd-name", string(got))
	}
}

func TestJSONSyscallEventClampsMemfdNamePayloadSection(t *testing.T) {
	name := bytes.Repeat([]byte{'a'}, memfdNamePayloadMaxBytes+10)
	capturedName := name[:memfdNamePayloadMaxBytes]
	eventRaw := &bpfEvent{
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{0x2000, 0},
		ProbeRetEnter: 0,
	}
	setJSONTestTLVPayload(t, eventRaw, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: eventRaw.Args[0],
		userLen: uint32(len(capturedName)),
		data:    capturedName,
	})

	scMeta := meta.Syscall{Name: "memfd_create"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.UserLen != memfdNamePayloadMaxBytes || section.CopiedLen != memfdNamePayloadMaxBytes {
		t.Fatalf("memfd_create clamped bounds = %+v", section)
	}
}

func TestJSONSyscallEventIncludesProcessVMIovecPayloadSections(t *testing.T) {
	localData := []byte("local-iovec-0000")
	remoteData := []byte("remote-iovec-000")
	eventRaw := &bpfEvent{
		Pid:           101,
		Tid:           101,
		EventVersion:  2,
		EventType:     bpfEventTypeEnter,
		Args:          [6]uint64{102, 0x3000, 1, 0x4000, 1, 0},
		ProbeRetEnter: 0,
	}
	setJSONTestTLVPayload(t, eventRaw,
		payloadTLVTestSection{
			kind:    payloadTLVKindIovec,
			arg:     1,
			userPtr: eventRaw.Args[1],
			userLen: uint32(len(localData)),
			data:    localData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindIovec,
			arg:     3,
			userPtr: eventRaw.Args[3],
			userLen: uint32(len(remoteData)),
			data:    remoteData,
		},
	)

	scMeta := meta.Syscall{Name: "process_vm_readv"}
	ev := newJSONSyscallEvent(eventRaw, scMeta, payloadSectionsForEvent(eventRaw, scMeta))
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want 2", len(ev.PayloadSections))
	}
	local := ev.PayloadSections[0]
	remote := ev.PayloadSections[1]
	if local.Kind != "iovec" || local.ArgIndex != 1 || local.UserPtr != 0x3000 {
		t.Fatalf("local iovec section = %+v", local)
	}
	if remote.Kind != "iovec" || remote.ArgIndex != 3 || remote.UserPtr != 0x4000 {
		t.Fatalf("remote iovec section = %+v", remote)
	}
}
