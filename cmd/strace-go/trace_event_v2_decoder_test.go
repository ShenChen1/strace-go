package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/ringbuf"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

func TestDecodeTraceEventV2EnterEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     102,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV | bpfEventFlagGenericEnter,
		tsNs:    900,
		args:    args,
		payload: payload,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid enter sample")
	}
	if !envelope.valid || envelope.eventVersion != traceEventV2Version || envelope.eventType != bpfEventTypeEnter {
		t.Fatalf("enter envelope = %+v, want valid v2 enter", envelope)
	}
	if envelope.pid != 101 || envelope.tid != 102 || envelope.sysID != sysID || envelope.enterTime != 900 {
		t.Fatalf("enter envelope identity = %+v", envelope)
	}
	if envelope.eventFlags&bpfEventFlagGenericEnter == 0 || envelope.eventFlags&bpfEventFlagPayloadTLV == 0 {
		t.Fatalf("enter event flags = %#x, want generic enter and TLV", envelope.eventFlags)
	}
	if envelope.args != args {
		t.Fatalf("enter args = %+v, want %+v", envelope.args, args)
	}
	assertTraceEventV2PathSection(t, envelope.payload)
}

func TestDecodeTraceEventV2EnvelopeCapturesTaskComm(t *testing.T) {
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:   103,
		tid:   104,
		sysID: syscallIDByName(t, "getpid"),
		comm:  "worker",
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a sample with task comm")
	}
	if envelope.comm != "worker" {
		t.Fatalf("task comm = %q, want worker", envelope.comm)
	}
}

func TestDecodeTraceEventV2EnterFragmentEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "bpf")
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     143,
		userPtr: 0x2000,
		userLen: 8,
		data:    []byte("lineinfo"),
	})
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     201,
		tid:     202,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV | bpfEventFlagEnterFragment,
		tsNs:    1200,
		args:    [6]uint64{1, 2, 3},
		payload: payload,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid enter fragment")
	}
	if envelope.eventType != bpfEventTypeEnter || envelope.eventFlags&bpfEventFlagEnterFragment == 0 {
		t.Fatalf("enter fragment envelope = %+v, want enter fragment", envelope)
	}
	if envelope.eventFlags&bpfEventFlagGenericEnter != 0 {
		t.Fatalf("enter fragment was misclassified as generic enter: flags=%#x", envelope.eventFlags)
	}
	if len(envelope.payload) != 1 || envelope.payload[0].ArgIndex != 143 {
		t.Fatalf("enter fragment payload = %+v, want arg 143", envelope.payload)
	}
}

func TestDecodeTraceEventV2CompactEnterEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "getpid")
	args := [6]uint64{1, 2, 3, 4, 5, 6}
	raw := traceEventV2CompactEnterSample(t, traceEventV2SampleSpec{
		pid:   101,
		tid:   102,
		sysID: sysID,
		flags: bpfEventFlagGenericEnter | bpfEventFlagCompactEnter,
		tsNs:  900,
		args:  args,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected compact enter")
	}
	if envelope.args != args || envelope.enterTime != 900 {
		t.Fatalf("compact enter = %+v, want args/time %#v/900", envelope, args)
	}
	if envelope.probeRetEnter != -1 || envelope.probeRetExit != -1 || len(envelope.payload) != 0 {
		t.Fatalf("compact enter unavailable fields = %+v, want probe -1 and no payload", envelope)
	}
}

func TestDecodeTraceEventV2RejectsInvalidCompactEnter(t *testing.T) {
	raw := traceEventV2CompactEnterSample(t, traceEventV2SampleSpec{
		sysID: syscallIDByName(t, "getpid"),
		flags: bpfEventFlagGenericEnter | bpfEventFlagCompactEnter,
	})
	if _, ok := decodeTraceEventV2Envelope(raw[:len(raw)-1]); ok {
		t.Fatal("decoder accepted truncated compact enter")
	}
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderFlagsOffset:traceEventV2HeaderFlagsOffset+traceEventV2U16Size], uint16(bpfEventFlagGenericEnter|bpfEventFlagCompactEnter|bpfEventFlagPayloadTLV))
	if _, ok := decodeTraceEventV2Envelope(raw); ok {
		t.Fatal("decoder accepted compact enter with payload flag")
	}
}

func TestDecodeTraceEventV2EnterEnvelopePreservesStatus(t *testing.T) {
	sysID := syscallIDByName(t, "execve")
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:           301,
		tid:           301,
		sysID:         sysID,
		tsNs:          1200,
		ret:           -514,
		probeRetEnter: 0,
		probeRetExit:  -1,
		args:          [6]uint64{0x1000, 0x2000, 0x3000},
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid status enter sample")
	}
	if envelope.ret != -514 || envelope.probeRetEnter != 0 || envelope.probeRetExit != -1 {
		t.Fatalf("enter status = ret:%d probe_enter:%d probe_exit:%d, want -514/0/-1",
			envelope.ret, envelope.probeRetEnter, envelope.probeRetExit)
	}
}

func TestTraceRingbufRecordDecoderAcceptsTraceEventV2Sample(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     102,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV | bpfEventFlagGenericEnter,
		tsNs:    900,
		args:    [6]uint64{rawAtFdcwd, 0x1000},
		payload: payload,
	})

	envelope, ok := newTraceRingbufRecordDecoder().Decode(&ringbuf.Record{RawSample: raw})
	if !ok {
		t.Fatal("record decoder rejected a valid v2 sample")
	}
	assertTraceEventV2PathSection(t, envelope.payload)
}

func TestTraceEventV2OpenatExitMatchesPathFilter(t *testing.T) {
	sysID := syscallIDByName(t, "openat")
	args := [6]uint64{rawAtFdcwd, 0x1000, 0}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindString,
		arg:     1,
		userPtr: 0x1000,
		userLen: 9,
		data:    []byte("v2.txt\x00"),
	})
	enterRaw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     101,
		tid:     101,
		sysID:   sysID,
		flags:   bpfEventFlagPayloadTLV | bpfEventFlagGenericEnter,
		tsNs:    900,
		args:    args,
		payload: payload,
	})
	exitRaw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:      101,
		tid:      101,
		sysID:    sysID,
		tsNs:     950,
		duration: 50,
		ret:      -2,
		args:     args,
	})

	state := newTraceState()
	enterEnvelope, ok := decodeTraceEventV2Envelope(enterRaw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected enter")
	}
	state.handleEnvelope(enterEnvelope)
	exitEnvelope, ok := decodeTraceEventV2Envelope(exitRaw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected exit")
	}
	update := state.handleEnvelope(exitEnvelope)
	session := newBareTestTraceSessionWithOptions(cli.ParseArgs([]string{"-e", "trace=openat", "-P", "v2.txt", "/bin/true"}), traceSessionDeps{
		TargetPID: 101,
		Decoder:   event.NewDecoder(),
		FDState:   newFDStateStoreFromMaps(nil, nil),
	})

	ev := newSyscallEventContextFromView(session, update.syscallView, 101, update.pendingEnter, update.payloadSections)

	if !ev.shouldOutput() {
		t.Fatalf("v2 openat exit did not match -P from pending payload: view=%+v pending=%+v", update.syscallView, update.pendingEnter)
	}
	if ev.pathText != `"v2.txt"` {
		t.Fatalf("pathText = %q, want quoted BPF snapshot", ev.pathText)
	}
}

func TestDecodeTraceEventV2ExitEnvelope(t *testing.T) {
	sysID := syscallIDByName(t, "read")
	args := [6]uint64{3, 0x2000, 16}
	payload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: 0x2000,
		userLen: 4,
		data:    []byte("data"),
	})
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:         201,
		tid:         202,
		sysID:       sysID,
		flags:       bpfEventFlagPayloadTLV,
		tsNs:        1000,
		duration:    55,
		cpuDuration: 7,
		ret:         4,
		args:        args,
		payload:     payload,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid exit sample")
	}
	if envelope.ret != 4 || envelope.duration != 55 || envelope.cpuDuration != 7 || envelope.enterTime != 945 {
		t.Fatalf("exit result fields = ret %d wall %d CPU %d enter %d", envelope.ret, envelope.duration, envelope.cpuDuration, envelope.enterTime)
	}
	if len(envelope.payload) != 1 || envelope.payload[0].Direction != handler.PayloadDirectionOut ||
		!bytes.Equal(envelope.payload[0].Data, []byte("data")) {
		t.Fatalf("exit payload = %+v, want OUT bytes section", envelope.payload)
	}
}

func TestDecodeTraceEventV2ExitEnvelopePreservesStackID(t *testing.T) {
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:     501,
		tid:     502,
		sysID:   syscallIDByName(t, "chdir"),
		tsNs:    1200,
		stackID: 17,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected an exit sample with stack id")
	}
	if envelope.stackID != 17 {
		t.Fatalf("exit stackID = %d, want 17", envelope.stackID)
	}
}

func TestDecodeTraceEventV2ExitEnvelopePreservesKVMReason(t *testing.T) {
	raw := traceEventV2ExitSample(t, traceEventV2SampleSpec{
		pid:           601,
		tid:           602,
		sysID:         syscallIDByName(t, "ioctl"),
		flags:         bpfEventFlagKVMExit,
		args:          [6]uint64{3, kvmRunIOCTL, 0},
		kvmExitReason: 6,
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a KVM exit sample")
	}
	if envelope.kvmExitReason != 6 || envelope.syscallView().kvmExitReason != 6 {
		t.Fatalf("KVM exit reason = envelope:%d view:%d, want 6", envelope.kvmExitReason, envelope.syscallView().kvmExitReason)
	}
}

func TestDecodeTraceEventV2LifecycleEnvelope(t *testing.T) {
	raw := traceEventV2LifecycleSample(t, traceEventV2SampleSpec{
		pid:     401,
		tid:     402,
		tsNs:    1200,
		action:  lifecycleExec,
		args:    [6]uint64{400, 401},
		payload: []byte("/bin/true\x00trailing"),
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a lifecycle sample")
	}
	if !envelope.valid || envelope.eventVersion != traceEventV2Version ||
		envelope.eventType != bpfEventTypeLifecycle || envelope.lifecycleAction != lifecycleExec {
		t.Fatalf("lifecycle envelope = %+v, want valid exec lifecycle", envelope)
	}
	if envelope.pid != 401 || envelope.tid != 402 || envelope.args[0] != 400 ||
		envelope.args[1] != 401 || envelope.enterTime != 1200 {
		t.Fatalf("lifecycle identity = %+v", envelope)
	}
	if envelope.snapshotText != "/bin/true" {
		t.Fatalf("lifecycle snapshot = %q, want /bin/true", envelope.snapshotText)
	}
}

func TestDecodeTraceEventV2RejectsWindowPayloadFallback(t *testing.T) {
	sysID := syscallIDByName(t, "chdir")
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:     301,
		tid:     302,
		sysID:   sysID,
		tsNs:    700,
		args:    [6]uint64{0x3000},
		payload: []byte("v2-fixed.txt\x00"),
	})

	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok {
		t.Fatal("decodeTraceEventV2Envelope rejected a valid non-TLV event v2 sample")
	}
	if envelope.eventFlags&bpfEventFlagPayloadTLV != 0 {
		t.Fatalf("event flags = %#x, want no inferred TLV flag", envelope.eventFlags)
	}
	if len(envelope.payload) != 0 {
		t.Fatalf("payload sections = %+v, want no fixed-window fallback", envelope.payload)
	}
}

func TestDecodeTraceEventV2RejectsShortCapture(t *testing.T) {
	raw := traceEventV2EnterSample(t, traceEventV2SampleSpec{
		pid:   101,
		tid:   102,
		sysID: 39,
		tsNs:  900,
	})
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2EnterCaptureLenOffset:bodyOffset+traceEventV2EnterCaptureLenOffset+traceEventV2U32Size], 1)

	if _, ok := decodeTraceEventV2Envelope(raw); ok {
		t.Fatal("decodeTraceEventV2Envelope accepted a capture_len beyond the sample body")
	}
}

func assertTraceEventV2PathSection(t *testing.T, sections []handler.PayloadSection) {
	t.Helper()
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if section.Kind != handler.PayloadKindString || section.Direction != handler.PayloadDirectionIn ||
		section.ArgIndex != 1 || section.UserPtr != 0x1000 || section.UserLen != 9 {
		t.Fatalf("path section metadata = %+v", section)
	}
	if !bytes.Equal(section.Data, []byte("v2.txt\x00")) {
		t.Fatalf("path section data = %q", section.Data)
	}
}

func traceEventV2EnterSample(t testing.TB, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2EnterBodyLen + len(spec.payload)
	spec.eventType = bpfEventTypeEnter
	raw := traceEventV2HeaderSample(spec, size)
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2EnterRetOffset:bodyOffset+traceEventV2EnterRetOffset+traceEventV2U64Size], uint64(spec.ret))
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2EnterProbeRetEnterOffset:bodyOffset+traceEventV2EnterProbeRetEnterOffset+traceEventV2U32Size], uint32(spec.probeRetEnter))
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2EnterProbeRetExitOffset:bodyOffset+traceEventV2EnterProbeRetExitOffset+traceEventV2U32Size], uint32(spec.probeRetExit))
	putTraceEventV2Args(raw[bodyOffset+traceEventV2EnterArgsOffset:bodyOffset+traceEventV2EnterArgsOffset+traceEventV2ArgsSize], spec.args)
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2EnterCaptureLenOffset:bodyOffset+traceEventV2EnterCaptureLenOffset+traceEventV2U32Size], uint32(len(spec.payload)))
	copy(raw[bodyOffset+traceEventV2EnterBodyLen:], spec.payload)
	return raw
}

func traceEventV2CompactEnterSample(t *testing.T, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2CompactEnterBodyLen
	spec.eventType = bpfEventTypeEnter
	raw := traceEventV2HeaderSample(spec, size)
	putTraceEventV2Args(raw[traceEventV2HeaderLen+traceEventV2CompactEnterArgsOffset:traceEventV2HeaderLen+traceEventV2CompactEnterArgsOffset+traceEventV2ArgsSize], spec.args)
	return raw
}

func traceEventV2ExitSample(t *testing.T, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2ExitBodyLen + len(spec.payload)
	spec.eventType = bpfEventTypeExit
	raw := traceEventV2HeaderSample(spec, size)
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2ExitRetOffset:bodyOffset+traceEventV2ExitRetOffset+traceEventV2U64Size], uint64(spec.ret))
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2ExitDurationOffset:bodyOffset+traceEventV2ExitDurationOffset+traceEventV2U64Size], spec.duration)
	binary.LittleEndian.PutUint64(raw[bodyOffset+traceEventV2ExitCPUDurationOffset:bodyOffset+traceEventV2ExitCPUDurationOffset+traceEventV2U64Size], spec.cpuDuration)
	putTraceEventV2Args(raw[bodyOffset+traceEventV2ExitArgsOffset:bodyOffset+traceEventV2ExitArgsOffset+traceEventV2ArgsSize], spec.args)
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2ExitCaptureLenOffset:bodyOffset+traceEventV2ExitCaptureLenOffset+traceEventV2U32Size], uint32(len(spec.payload)))
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2ExitStackIDOffset:bodyOffset+traceEventV2ExitStackIDOffset+traceEventV2U32Size], uint32(spec.stackID))
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2ExitReservedOffset:bodyOffset+traceEventV2ExitReservedOffset+traceEventV2U32Size], spec.kvmExitReason)
	copy(raw[bodyOffset+traceEventV2ExitBodyLen:], spec.payload)
	return raw
}

func traceEventV2LifecycleSample(t *testing.T, spec traceEventV2SampleSpec) []byte {
	t.Helper()
	size := traceEventV2HeaderLen + traceEventV2LifecycleBodyLen + len(spec.payload)
	spec.eventType = bpfEventTypeLifecycle
	raw := traceEventV2HeaderSample(spec, size)
	bodyOffset := traceEventV2HeaderLen
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2LifecycleActionOffset:bodyOffset+traceEventV2LifecycleActionOffset+traceEventV2U32Size], spec.action)
	binary.LittleEndian.PutUint32(raw[bodyOffset+traceEventV2LifecycleSnapshotLenOffset:bodyOffset+traceEventV2LifecycleSnapshotLenOffset+traceEventV2U32Size], uint32(len(spec.payload)))
	putTraceEventV2Args(raw[bodyOffset+traceEventV2LifecycleArgsOffset:bodyOffset+traceEventV2LifecycleArgsOffset+traceEventV2ArgsSize], spec.args)
	copy(raw[bodyOffset+traceEventV2LifecycleBodyLen:], spec.payload)
	return raw
}

func traceEventV2HeaderSample(spec traceEventV2SampleSpec, size int) []byte {
	raw := make([]byte, size)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderVersionOffset:traceEventV2HeaderVersionOffset+traceEventV2U16Size], traceEventV2Version)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderEventTypeOffset:traceEventV2HeaderEventTypeOffset+traceEventV2U16Size], spec.eventType)
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderFlagsOffset:traceEventV2HeaderFlagsOffset+traceEventV2U16Size], uint16(spec.flags))
	binary.LittleEndian.PutUint16(raw[traceEventV2HeaderLenOffset:traceEventV2HeaderLenOffset+traceEventV2U16Size], traceEventV2HeaderLen)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSizeOffset:traceEventV2HeaderSizeOffset+traceEventV2U32Size], uint32(size))
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderPIDOffset:traceEventV2HeaderPIDOffset+traceEventV2U32Size], spec.pid)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderTIDOffset:traceEventV2HeaderTIDOffset+traceEventV2U32Size], spec.tid)
	binary.LittleEndian.PutUint32(raw[traceEventV2HeaderSysIDOffset:traceEventV2HeaderSysIDOffset+traceEventV2U32Size], spec.sysID)
	binary.LittleEndian.PutUint64(raw[traceEventV2HeaderTSNSOffset:traceEventV2HeaderTSNSOffset+traceEventV2U64Size], spec.tsNs)
	copy(raw[traceEventV2HeaderCommOffset:traceEventV2HeaderCommOffset+traceEventV2CommSize], spec.comm)
	return raw
}

func putTraceEventV2Args(data []byte, args [6]uint64) {
	for i, arg := range args {
		binary.LittleEndian.PutUint64(data[i*8:i*8+8], arg)
	}
}
