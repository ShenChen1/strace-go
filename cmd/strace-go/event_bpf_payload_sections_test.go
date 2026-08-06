package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestJSONSyscallEventIncludesBpfAttrPayloadSection(t *testing.T) {
	wantData := bytes.Repeat([]byte{0x5a}, 32)
	args := [6]uint64{0, 0x1000, uint64(len(wantData))}
	payload := payloadTLVBytesForTest(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: 0x1000,
		userLen: uint32(len(wantData)),
		data:    wantData,
	})

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 1 {
		t.Fatalf("PayloadSections = %d, want 1", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[0]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 1 {
		t.Fatalf("bpf section metadata = %+v", section)
	}
	if section.UserPtr != 0x1000 {
		t.Fatalf("bpf section bounds = %+v", section)
	}
	if section.UserLen != uint32(len(wantData)) || section.CopiedLen != uint32(len(wantData)) {
		t.Fatalf("bpf section lengths = %+v, want %d", section, len(wantData))
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, wantData) {
		t.Fatalf("bpf section data length = %d, want %d", len(data), len(wantData))
	}
}

func TestJSONSyscallEventIncludesBpfProgLoadNestedPayloadSections(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x7b}, 40)
	insnsData := bpfKprobeU64JSONData(0xbadc0ded0000ba95)
	licenseData := []byte("GPL\x00")
	logData := []byte("log ")
	signatureData := []byte{1, 2, 3}
	args := [6]uint64{5, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     112,
			userPtr: 0x2000,
			userLen: uint32(len(insnsData)),
			data:    insnsData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindString,
			arg:     101,
			userPtr: 0x3000,
			userLen: uint32(len(licenseData)),
			data:    licenseData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     102,
			userPtr: 0x4000,
			userLen: uint32(len(logData)),
			data:    logData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     103,
			userPtr: 0x5000,
			userLen: uint32(len(signatureData)),
			data:    signatureData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 5 {
		t.Fatalf("PayloadSections = %d, want attr, insns, license, log_buf, signature", len(ev.PayloadSections))
	}
	if ev.PayloadSections[1].Kind != "bytes" || ev.PayloadSections[1].ArgIndex != 112 {
		t.Fatalf("insns section = %+v", ev.PayloadSections[1])
	}
	if ev.PayloadSections[2].Kind != "string" || ev.PayloadSections[2].ArgIndex != 101 {
		t.Fatalf("license section = %+v", ev.PayloadSections[2])
	}
	if ev.PayloadSections[3].Kind != "bytes" || ev.PayloadSections[3].ArgIndex != 102 {
		t.Fatalf("log_buf section = %+v", ev.PayloadSections[3])
	}
	if ev.PayloadSections[4].Kind != "bytes" || ev.PayloadSections[4].ArgIndex != 103 {
		t.Fatalf("signature section = %+v", ev.PayloadSections[4])
	}
	if data := mustDecodeBase64(t, ev.PayloadSections[1].DataBase64); !bytes.Equal(data, insnsData) {
		t.Fatalf("insns section data = %v", data)
	}
	if data := mustDecodeBase64(t, ev.PayloadSections[2].DataBase64); !bytes.Equal(data, licenseData) {
		t.Fatalf("license section data = %q", string(data))
	}
	if data := mustDecodeBase64(t, ev.PayloadSections[3].DataBase64); !bytes.Equal(data, logData) {
		t.Fatalf("log_buf section data = %q", string(data))
	}
	if data := mustDecodeBase64(t, ev.PayloadSections[4].DataBase64); !bytes.Equal(data, signatureData) {
		t.Fatalf("signature section data = %v", data)
	}
}

func TestJSONSyscallEventIncludesBpfObjPathnamePayloadSection(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x11}, 12)
	pathData := []byte("/sys/fs/bpf/test\x00")
	args := [6]uint64{6, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindString,
			arg:     104,
			userPtr: 0x3000,
			userLen: uint32(len(pathData)),
			data:    pathData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want attr and pathname", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[1]
	if section.Kind != "string" || section.Direction != "in" || section.ArgIndex != 104 {
		t.Fatalf("pathname section = %+v", section)
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, pathData) {
		t.Fatalf("pathname section data = %q", string(data))
	}
}

func TestJSONSyscallEventIncludesBpfRawTracepointNamePayloadSection(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x22}, 24)
	nameData := []byte("sched_switch\x00")
	args := [6]uint64{17, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindString,
			arg:     105,
			userPtr: 0x4000,
			userLen: uint32(len(nameData)),
			data:    nameData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want attr and raw tracepoint name", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[1]
	if section.Kind != "string" || section.Direction != "in" || section.ArgIndex != 105 {
		t.Fatalf("raw tracepoint name section = %+v", section)
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, nameData) {
		t.Fatalf("raw tracepoint name data = %q", string(data))
	}
}

func TestJSONSyscallEventIncludesBpfBtfPayloadSection(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x33}, 28)
	btfData := []byte("bPf\x00daTum")
	args := [6]uint64{18, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     106,
			userPtr: 0x5000,
			userLen: uint32(len(btfData)),
			data:    btfData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want attr and btf bytes", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[1]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 106 {
		t.Fatalf("btf section = %+v", section)
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, btfData) {
		t.Fatalf("btf data = %q", string(data))
	}
}

func TestJSONSyscallEventIncludesBpfLinkIterInfoPayloadSection(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x44}, 28)
	iterData := []byte{0, 0, 0, 0, 42, 0, 0, 0}
	args := [6]uint64{28, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     107,
			userPtr: 0x6000,
			userLen: uint32(len(iterData)),
			data:    iterData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want attr and link iter_info", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[1]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 107 {
		t.Fatalf("link iter_info section = %+v", section)
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, iterData) {
		t.Fatalf("link iter_info data = %v", data)
	}
}

func TestJSONSyscallEventIncludesBpfKprobeMultiPayloadSections(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x55}, 48)
	symsData := bpfKprobeSymsJSONData()
	addrsData := bpfKprobeU64JSONData(0, 1, 0xbadc0ded, 0xfacefeeddeadc0de)
	cookiesData := bpfKprobeU64JSONData(0, 1, 0xbadc0ded, 0xfacefeeddeadc0de)
	args := [6]uint64{28, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     108,
			userPtr: 0x6000,
			userLen: uint32(len(symsData)),
			data:    symsData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     109,
			userPtr: 0x7000,
			userLen: uint32(len(addrsData)),
			data:    addrsData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     110,
			userPtr: 0x8000,
			userLen: uint32(len(cookiesData)),
			data:    cookiesData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 4 {
		t.Fatalf("PayloadSections = %d, want attr and kprobe_multi sections", len(ev.PayloadSections))
	}
	for i, arg := range []int{108, 109, 110} {
		section := ev.PayloadSections[i+1]
		if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != arg {
			t.Fatalf("kprobe_multi section %d = %+v", i, section)
		}
	}
}

func TestJSONSyscallEventIncludesBpfProgStreamReadPayloadSection(t *testing.T) {
	attrData := bytes.Repeat([]byte{0x66}, 20)
	streamData := []byte("bPf\x00daTum")
	args := [6]uint64{37, 0x1000, uint64(len(attrData))}
	payload := payloadTLVBytesForTest(t,
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     1,
			userPtr: args[1],
			userLen: uint32(len(attrData)),
			data:    attrData,
		},
		payloadTLVTestSection{
			kind:    payloadTLVKindBytes,
			arg:     111,
			userPtr: 0x9000,
			userLen: uint32(len(streamData)),
			data:    streamData,
		},
	)

	ev := newJSONSyscallEventFromTLVForTest(t, "bpf", bpfEventTypeEnter, args, 0, payload)
	if len(ev.PayloadSections) != 2 {
		t.Fatalf("PayloadSections = %d, want attr and stream_buf", len(ev.PayloadSections))
	}
	section := ev.PayloadSections[1]
	if section.Kind != "bytes" || section.Direction != "in" || section.ArgIndex != 111 {
		t.Fatalf("stream_buf section = %+v", section)
	}
	if data := mustDecodeBase64(t, section.DataBase64); !bytes.Equal(data, streamData) {
		t.Fatalf("stream_buf data = %q", string(data))
	}
}

func bpfKprobeSymsJSONData() []byte {
	const (
		recordSize = 52
		dataSize   = 40
	)
	data := make([]byte, 4*recordSize)
	records := []struct {
		ptr    uint64
		length int32
		text   []byte
	}{
		{ptr: 0x2000, length: 4, text: []byte("foo\x00")},
		{},
		{ptr: 0x3000, length: 3, text: []byte("OH\x00")},
		{ptr: 0x4000, length: dataSize, text: []byte("abcdefghijklmnopqrstuvwxyz0123456789")},
	}
	for i, record := range records {
		offset := i * recordSize
		binary.LittleEndian.PutUint64(data[offset:offset+8], record.ptr)
		binary.LittleEndian.PutUint32(data[offset+8:offset+12], uint32(record.length))
		copy(data[offset+12:offset+12+dataSize], record.text)
	}
	return data
}

func bpfKprobeU64JSONData(vals ...uint64) []byte {
	data := make([]byte, len(vals)*8)
	for i, val := range vals {
		binary.LittleEndian.PutUint64(data[i*8:i*8+8], val)
	}
	return data
}
