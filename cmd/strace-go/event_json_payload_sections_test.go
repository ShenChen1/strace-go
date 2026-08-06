package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/meta"
)

const memfdNamePayloadMaxBytes = 250

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
			payload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindBytes,
				flags:   payloadTLVFlagDirectionOut,
				arg:     uint16(tt.argIndex),
				userPtr: tt.args[tt.argIndex],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, bpfEventTypeExit, tt.args, 6, payload)
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
			payload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   payloadTLVFlagDirectionOut,
				arg:     uint16(tt.argIndex),
				userPtr: tt.args[tt.argIndex],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, bpfEventTypeExit, tt.args, 0, payload)
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
	scMeta := meta.Syscall{Name: "fstat"}
	ev := newJSONSyscallEventFromView(syscallEventView{
		valid:         true,
		eventType:     bpfEventTypeExit,
		args:          [6]uint64{3, 0x2000},
		ret:           -2,
		probeRetEnter: -1,
		probeRetExit:  0,
	}, scMeta, nil)
	if len(ev.PayloadSections) != 0 {
		t.Fatalf("PayloadSections = %+v, want none for failed fstat", ev.PayloadSections)
	}
}

func TestJSONSyscallEventIncludesPollStructPayloadSections(t *testing.T) {
	enterData := []byte("pollfd-enter-000")
	exitData := []byte("pollfd-exit--000")
	args := [6]uint64{0x2000, 2, 1000}
	payload := payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(enterData)),
			data:    enterData,
		})
	payload = append(payload, payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			flags:   payloadTLVFlagDirectionOut,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(exitData)),
			data:    exitData,
		})...)

	ev := newJSONSyscallEventFromTLVForTest(t, "poll", bpfEventTypeExit, args, 1, payload)
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
	args := [6]uint64{0x2000, 1, 0x3000}
	payload := payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     0,
			userPtr: args[0],
			userLen: uint32(len(pollfdsData)),
			data:    pollfdsData,
		})
	payload = append(payload, payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindStruct,
			arg:     2,
			userPtr: args[2],
			userLen: uint32(len(timeoutData)),
			data:    timeoutData,
		})...)

	ev := newJSONSyscallEventFromTLVForTest(t, "ppoll", bpfEventTypeEnter, args, 0, payload)
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
	assertJSONEpollStructPayloadSections(t, "epoll_ctl", bpfEventTypeEnter, [6]uint64{5, 1, 6, 0x3000}, 0, 1, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     3,
		userPtr: 0x3000,
		userLen: epollPayloadEventSize,
		data:    bytes.Repeat([]byte{0x11}, epollPayloadEventSize),
	})
}

func TestJSONSyscallEventIncludesEpollWaitStructPayloadSection(t *testing.T) {
	assertJSONEpollStructPayloadSections(t, "epoll_wait", bpfEventTypeExit, [6]uint64{5, 0x2000, 2, 1000}, 2, 1, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 24,
		data:    bytes.Repeat([]byte{0x33}, 24),
	})
}

func TestJSONSyscallEventIncludesEpollPwait2StructPayloadSections(t *testing.T) {
	assertJSONEpollStructPayloadSections(t, "epoll_pwait2", bpfEventTypeExit, [6]uint64{5, 0x2000, 2, 0x3000, 0, 8}, 2, 2,
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
	eventType uint16,
	args [6]uint64,
	ret int64,
	wantCount int,
	sections ...payloadTLVTestSection,
) {
	t.Helper()
	var payload []byte
	for _, section := range sections {
		payload = append(payload, payloadTLVBytes(t, section)...)
	}
	ev := newJSONSyscallEventFromTLVForTest(t, name, eventType, args, ret, payload)
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
			payload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindIovec,
				arg:     1,
				userPtr: tt.args[1],
				userLen: uint32(len(wantData)),
				data:    wantData,
			})

			ev := newJSONSyscallEventFromTLVForTest(t, tt.name, bpfEventTypeEnter, tt.args, 0, payload)
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
	args := [6]uint64{0x2000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(nameData)),
		data:    nameData,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "memfd_create", bpfEventTypeEnter, args, 0, payload)
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
	args := [6]uint64{0x2000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     0,
		userPtr: args[0],
		userLen: uint32(len(capturedName)),
		data:    capturedName,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "memfd_create", bpfEventTypeEnter, args, 0, payload)
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
	baseData := []byte{0x80, 0x81, 0x82, 0x83, 0x84}
	args := [6]uint64{102, 0x3000, 1, 0x4000, 1, 0}
	payload := payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindIovec,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(localData)),
			data:    localData,
		})
	payload = append(payload, payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindIovec,
			arg:     3,
			userPtr: args[3],
			userLen: uint32(len(remoteData)),
			data:    remoteData,
		})...)
	payload = append(payload, payloadTLVBytes(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     120,
			userPtr: 0x5000,
			userLen: 6,
			data:    baseData,
		})...)

	ev := newJSONSyscallEventFromTLVForTest(t, "process_vm_writev", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 3 {
		t.Fatalf("PayloadSections = %d, want 3", len(ev.PayloadSections))
	}
	local := ev.PayloadSections[0]
	remote := ev.PayloadSections[1]
	base := ev.PayloadSections[2]
	if local.Kind != "iovec" || local.ArgIndex != 1 || local.UserPtr != 0x3000 {
		t.Fatalf("local iovec section = %+v", local)
	}
	if remote.Kind != "iovec" || remote.ArgIndex != 3 || remote.UserPtr != 0x4000 {
		t.Fatalf("remote iovec section = %+v", remote)
	}
	if base.Kind != "bytes" || base.ArgIndex != 120 || base.UserPtr != 0x5000 || base.UserLen != 6 {
		t.Fatalf("local iov_base section = %+v", base)
	}
	if got := mustDecodeBase64(t, base.DataBase64); !bytes.Equal(got, baseData) {
		t.Fatalf("local iov_base data = %v, want %v", got, baseData)
	}
}
