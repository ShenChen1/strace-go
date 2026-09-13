package main

import (
	"bytes"
	"encoding/binary"

	"strace-go/pkg/handler"
)

type traceEventV2Header struct {
	legacy     bool
	seq        uint64
	cpu        uint32
	lossEpoch  uint64
	lossTimeNS uint64
	version    uint16
	eventType  uint16
	flags      uint16
	pid        uint32
	tid        uint32
	sysID      uint32
	tsNs       uint64
	comm       string
}

func isTraceEventV2Sample(rawSample []byte) bool {
	_, _, ok := decodeTraceEventV2Header(rawSample)
	return ok
}

func decodeTraceEventV2Envelope(rawSample []byte) (traceEventEnvelope, bool) {
	return decodeTraceEventV2EnvelopeInto(rawSample, nil)
}

func decodeTraceEventV2EnvelopeInto(
	rawSample []byte,
	payloadScratch *[]handler.PayloadSection,
) (traceEventEnvelope, bool) {
	if payloadScratch != nil {
		*payloadScratch = (*payloadScratch)[:0]
	}
	header, body, ok := decodeTraceEventV2Header(rawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	var envelope traceEventEnvelope
	switch header.eventType {
	case bpfEventTypeEnter:
		envelope, ok = decodeTraceEventV2EnterEnvelope(header, body, payloadScratch)
	case bpfEventTypeExit:
		envelope, ok = decodeTraceEventV2ExitEnvelope(header, body, payloadScratch)
	case bpfEventTypeLifecycle:
		envelope, ok = decodeTraceEventV2LifecycleEnvelope(header, body)
	case bpfEventTypeSignal:
		envelope, ok = decodeTraceEventV2SignalEnvelope(header, body)
	default:
		return traceEventEnvelope{}, false
	}
	envelope.seq = header.seq
	envelope.legacyIntegrity = header.legacy
	envelope.cpu = header.cpu
	envelope.lossEpoch = header.lossEpoch
	envelope.lossTimeNS = header.lossTimeNS
	envelope.recordTime = header.tsNs
	return envelope, ok
}

func decodeTraceEventV2Header(rawSample []byte) (traceEventV2Header, []byte, bool) {
	if len(rawSample) < traceEventV2BaseHeaderLen {
		return traceEventV2Header{}, nil, false
	}
	version := binary.LittleEndian.Uint16(rawSample[traceEventV2HeaderVersionOffset : traceEventV2HeaderVersionOffset+traceEventV2U16Size])
	eventType := binary.LittleEndian.Uint16(rawSample[traceEventV2HeaderEventTypeOffset : traceEventV2HeaderEventTypeOffset+traceEventV2U16Size])
	headerLen := binary.LittleEndian.Uint16(rawSample[traceEventV2HeaderLenOffset : traceEventV2HeaderLenOffset+traceEventV2U16Size])
	size := binary.LittleEndian.Uint32(rawSample[traceEventV2HeaderSizeOffset : traceEventV2HeaderSizeOffset+traceEventV2U32Size])
	if version != traceEventV2Version ||
		(eventType != bpfEventTypeEnter && eventType != bpfEventTypeExit &&
			eventType != bpfEventTypeLifecycle && eventType != bpfEventTypeSignal) ||
		(headerLen != traceEventV2BaseHeaderLen && headerLen < traceEventV2HeaderLen) ||
		uint32(headerLen) > size ||
		size > uint32(len(rawSample)) {
		return traceEventV2Header{}, nil, false
	}
	headerLenInt := int(headerLen)
	sizeInt := int(size)
	header := traceEventV2Header{
		seq:       binary.LittleEndian.Uint64(rawSample[traceEventV2HeaderSeqOffset:]),
		version:   version,
		eventType: eventType,
		flags:     binary.LittleEndian.Uint16(rawSample[traceEventV2HeaderFlagsOffset : traceEventV2HeaderFlagsOffset+traceEventV2U16Size]),
		pid:       binary.LittleEndian.Uint32(rawSample[traceEventV2HeaderPIDOffset : traceEventV2HeaderPIDOffset+traceEventV2U32Size]),
		tid:       binary.LittleEndian.Uint32(rawSample[traceEventV2HeaderTIDOffset : traceEventV2HeaderTIDOffset+traceEventV2U32Size]),
		sysID:     binary.LittleEndian.Uint32(rawSample[traceEventV2HeaderSysIDOffset : traceEventV2HeaderSysIDOffset+traceEventV2U32Size]),
		tsNs:      binary.LittleEndian.Uint64(rawSample[traceEventV2HeaderTSNSOffset : traceEventV2HeaderTSNSOffset+traceEventV2U64Size]),
		comm:      decodeTraceEventV2Comm(rawSample[traceEventV2HeaderCommOffset : traceEventV2HeaderCommOffset+traceEventV2CommSize]),
	}
	header.legacy = headerLen == traceEventV2BaseHeaderLen
	if !header.legacy {
		header.cpu = binary.LittleEndian.Uint32(rawSample[traceEventV2HeaderCPUOffset:])
		header.lossEpoch = binary.LittleEndian.Uint64(rawSample[traceEventV2HeaderLossEpochOffset:])
		header.lossTimeNS = binary.LittleEndian.Uint64(rawSample[traceEventV2HeaderLossTimeOffset:])
	}
	return header, rawSample[headerLenInt:sizeInt], true
}

func decodeTraceEventV2EnterEnvelope(
	header traceEventV2Header,
	body []byte,
	payloadScratch *[]handler.PayloadSection,
) (traceEventEnvelope, bool) {
	if uint32(header.flags)&bpfEventFlagCompactEnter != 0 {
		return decodeTraceEventV2CompactEnterEnvelope(header, body)
	}
	if len(body) < traceEventV2EnterBodyLen {
		return traceEventEnvelope{}, false
	}
	ret := int64(binary.LittleEndian.Uint64(body[traceEventV2EnterRetOffset : traceEventV2EnterRetOffset+traceEventV2U64Size]))
	probeRetEnter := int32(binary.LittleEndian.Uint32(body[traceEventV2EnterProbeRetEnterOffset : traceEventV2EnterProbeRetEnterOffset+traceEventV2U32Size]))
	probeRetExit := int32(binary.LittleEndian.Uint32(body[traceEventV2EnterProbeRetExitOffset : traceEventV2EnterProbeRetExitOffset+traceEventV2U32Size]))
	args := traceEventV2Args(body[traceEventV2EnterArgsOffset : traceEventV2EnterArgsOffset+traceEventV2ArgsSize])
	captureLen := binary.LittleEndian.Uint32(body[traceEventV2EnterCaptureLenOffset : traceEventV2EnterCaptureLenOffset+traceEventV2U32Size])
	payload, ok := traceEventV2Payload(body, traceEventV2EnterBodyLen, captureLen)
	if !ok {
		return traceEventEnvelope{}, false
	}
	// IMPACT: the generic-enter flag must come from the BPF header; a blanket OR
	// here would misclassify the execve -514 restart marker as a generic enter
	// and swallow it before the exec output state machine can consume it.
	eventFlags := traceEventV2EventFlags(header, payload)
	raw := rawPayloadEvent{
		valid:         true,
		args:          args,
		eventType:     header.eventType,
		eventFlags:    eventFlags,
		ret:           ret,
		probeRetEnter: probeRetEnter,
		probeRetExit:  probeRetExit,
		data:          payload,
	}
	// IMPACT: sections borrow the current ringbuf record; TraceState takes
	// ownership only when it stores them beyond HandleRecord.
	sections := payloadSectionsForRawPayloadEventInto(raw, payloadScratch)
	return traceEventEnvelope{
		valid:         true,
		eventVersion:  header.version,
		pid:           header.pid,
		tid:           header.tid,
		comm:          header.comm,
		sysID:         header.sysID,
		eventType:     header.eventType,
		eventFlags:    eventFlags,
		enterTime:     header.tsNs,
		args:          args,
		ret:           ret,
		probeRetEnter: probeRetEnter,
		probeRetExit:  probeRetExit,
		payload:       sections,
	}, true
}

func decodeTraceEventV2CompactEnterEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	flags := uint32(header.flags)
	if len(body) != traceEventV2CompactEnterBodyLen ||
		flags&bpfEventFlagGenericEnter == 0 || flags&bpfEventFlagPayloadTLV != 0 {
		return traceEventEnvelope{}, false
	}
	args := traceEventV2Args(body[traceEventV2CompactEnterArgsOffset : traceEventV2CompactEnterArgsOffset+traceEventV2ArgsSize])
	eventFlags := traceEventV2EventFlags(header, nil)
	return traceEventEnvelope{
		valid:         true,
		eventVersion:  header.version,
		pid:           header.pid,
		tid:           header.tid,
		comm:          header.comm,
		sysID:         header.sysID,
		eventType:     header.eventType,
		eventFlags:    eventFlags,
		enterTime:     header.tsNs,
		args:          args,
		ret:           0,
		probeRetEnter: -1,
		probeRetExit:  -1,
	}, true
}

func decodeTraceEventV2ExitEnvelope(
	header traceEventV2Header,
	body []byte,
	payloadScratch *[]handler.PayloadSection,
) (traceEventEnvelope, bool) {
	if len(body) < traceEventV2ExitBodyLen {
		return traceEventEnvelope{}, false
	}
	ret := int64(binary.LittleEndian.Uint64(body[traceEventV2ExitRetOffset : traceEventV2ExitRetOffset+traceEventV2U64Size]))
	duration := binary.LittleEndian.Uint64(body[traceEventV2ExitDurationOffset : traceEventV2ExitDurationOffset+traceEventV2U64Size])
	cpuDuration := binary.LittleEndian.Uint64(body[traceEventV2ExitCPUDurationOffset : traceEventV2ExitCPUDurationOffset+traceEventV2U64Size])
	args := traceEventV2Args(body[traceEventV2ExitArgsOffset : traceEventV2ExitArgsOffset+traceEventV2ArgsSize])
	captureLen := binary.LittleEndian.Uint32(body[traceEventV2ExitCaptureLenOffset : traceEventV2ExitCaptureLenOffset+traceEventV2U32Size])
	stackID := int32(binary.LittleEndian.Uint32(body[traceEventV2ExitStackIDOffset : traceEventV2ExitStackIDOffset+traceEventV2U32Size]))
	kvmExitReason := binary.LittleEndian.Uint32(body[traceEventV2ExitReservedOffset : traceEventV2ExitReservedOffset+traceEventV2U32Size])
	payload, ok := traceEventV2Payload(body, traceEventV2ExitBodyLen, captureLen)
	if !ok {
		return traceEventEnvelope{}, false
	}
	eventFlags := traceEventV2EventFlags(header, payload)
	raw := rawPayloadEvent{
		valid:      true,
		args:       args,
		eventType:  header.eventType,
		eventFlags: eventFlags,
		ret:        ret,
		data:       payload,
	}
	// IMPACT: the exit pipeline consumes borrowed sections synchronously unless
	// TraceState first stores them as a deferred exit.
	sections := payloadSectionsForRawPayloadEventInto(raw, payloadScratch)
	return traceEventEnvelope{
		valid:         true,
		eventVersion:  header.version,
		pid:           header.pid,
		tid:           header.tid,
		comm:          header.comm,
		sysID:         header.sysID,
		eventType:     header.eventType,
		eventFlags:    eventFlags,
		enterTime:     traceEventV2EnterTime(header.tsNs, duration),
		args:          args,
		ret:           ret,
		duration:      duration,
		cpuDuration:   cpuDuration,
		stackID:       stackID,
		kvmExitReason: kvmExitReason,
		payload:       sections,
	}, true
}

func decodeTraceEventV2LifecycleEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	if len(body) < traceEventV2LifecycleBodyLen {
		return traceEventEnvelope{}, false
	}
	action := binary.LittleEndian.Uint32(body[traceEventV2LifecycleActionOffset : traceEventV2LifecycleActionOffset+traceEventV2U32Size])
	captureLen := binary.LittleEndian.Uint32(body[traceEventV2LifecycleSnapshotLenOffset : traceEventV2LifecycleSnapshotLenOffset+traceEventV2U32Size])
	args := traceEventV2Args(body[traceEventV2LifecycleArgsOffset : traceEventV2LifecycleArgsOffset+traceEventV2ArgsSize])
	if action == lifecycleFork {
		args[0] = uint64(uint32(args[0]))
	}
	payload, ok := traceEventV2Payload(body, traceEventV2LifecycleBodyLen, captureLen)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return traceEventEnvelope{
		valid:           true,
		eventVersion:    header.version,
		pid:             header.pid,
		tid:             header.tid,
		comm:            header.comm,
		eventType:       header.eventType,
		eventFlags:      traceEventV2EventFlags(header, payload),
		lifecycleAction: action,
		enterTime:       header.tsNs,
		args:            args,
		snapshotText:    lifecycleSnapshotString(payload),
	}, true
}

func decodeTraceEventV2SignalEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	if len(body) != traceEventV2SignalBodyLen {
		return traceEventEnvelope{}, false
	}
	return traceEventEnvelope{
		valid:            true,
		eventVersion:     header.version,
		pid:              header.pid,
		tid:              header.tid,
		comm:             header.comm,
		eventType:        header.eventType,
		enterTime:        header.tsNs,
		signal:           binary.LittleEndian.Uint32(body[traceEventV2SignalNumberOffset:]),
		signalErr:        int32(binary.LittleEndian.Uint32(body[traceEventV2SignalErrnoOffset:])),
		signalCode:       int32(binary.LittleEndian.Uint32(body[traceEventV2SignalCodeOffset:])),
		senderPID:        binary.LittleEndian.Uint32(body[traceEventV2SignalSenderPIDOffset:]),
		senderUID:        binary.LittleEndian.Uint32(body[traceEventV2SignalSenderUIDOffset:]),
		stackID:          int32(binary.LittleEndian.Uint32(body[traceEventV2SignalStackIDOffset:])),
		signalAddress:    binary.LittleEndian.Uint64(body[traceEventV2SignalAddressOffset:]),
		signalStatus:     int32(binary.LittleEndian.Uint32(body[traceEventV2SignalChildStatusOffset:])),
		signalUserTime:   int64(binary.LittleEndian.Uint64(body[traceEventV2SignalChildUserTimeOffset:])),
		signalSystemTime: int64(binary.LittleEndian.Uint64(body[traceEventV2SignalChildSystemTimeOffset:])),
	}, true
}

func decodeTraceEventV2Comm(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func traceEventV2Args(data []byte) [6]uint64 {
	var args [6]uint64
	for i := range args {
		args[i] = binary.LittleEndian.Uint64(data[i*traceEventV2U64Size : i*traceEventV2U64Size+traceEventV2U64Size])
	}
	return args
}

func traceEventV2Payload(body []byte, offset int, captureLen uint32) ([]byte, bool) {
	if offset < 0 || offset > len(body) {
		return nil, false
	}
	if captureLen > uint32(len(body)-offset) {
		return nil, false
	}
	return body[offset : offset+int(captureLen)], true
}

func traceEventV2EventFlags(header traceEventV2Header, payload []byte) uint32 {
	return uint32(header.flags)
}

func traceEventV2EnterTime(tsNs uint64, duration uint64) uint64 {
	if duration > tsNs {
		return tsNs
	}
	return tsNs - duration
}
