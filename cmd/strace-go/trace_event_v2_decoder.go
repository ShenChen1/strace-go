package main

import "encoding/binary"

const (
	traceEventV2Version          = 2
	traceEventV2HeaderLen        = 40
	traceEventV2EnterBodyLen     = 72
	traceEventV2ExitBodyLen      = 72
	traceEventV2LifecycleBodyLen = 56
)

type traceEventV2Header struct {
	version   uint16
	eventType uint16
	flags     uint16
	pid       uint32
	tid       uint32
	sysID     uint32
	tsNs      uint64
}

func isTraceEventV2Sample(rawSample []byte) bool {
	if len(rawSample) < traceEventV2HeaderLen {
		return false
	}
	if binary.LittleEndian.Uint16(rawSample[0:2]) != traceEventV2Version {
		return false
	}
	eventType := binary.LittleEndian.Uint16(rawSample[2:4])
	if eventType != bpfEventTypeEnter && eventType != bpfEventTypeExit &&
		eventType != bpfEventTypeLifecycle {
		return false
	}
	headerLen := binary.LittleEndian.Uint16(rawSample[6:8])
	size := binary.LittleEndian.Uint32(rawSample[8:12])
	return headerLen >= traceEventV2HeaderLen &&
		uint32(headerLen) <= size &&
		size <= uint32(len(rawSample))
}

func decodeTraceEventV2Envelope(rawSample []byte) (traceEventEnvelope, bool) {
	header, body, ok := decodeTraceEventV2Header(rawSample)
	if !ok {
		return traceEventEnvelope{}, false
	}
	switch header.eventType {
	case bpfEventTypeEnter:
		return decodeTraceEventV2EnterEnvelope(header, body)
	case bpfEventTypeExit:
		return decodeTraceEventV2ExitEnvelope(header, body)
	case bpfEventTypeLifecycle:
		return decodeTraceEventV2LifecycleEnvelope(header, body)
	default:
		return traceEventEnvelope{}, false
	}
}

func decodeTraceEventV2Header(rawSample []byte) (traceEventV2Header, []byte, bool) {
	if !isTraceEventV2Sample(rawSample) {
		return traceEventV2Header{}, nil, false
	}
	headerLen := int(binary.LittleEndian.Uint16(rawSample[6:8]))
	size := int(binary.LittleEndian.Uint32(rawSample[8:12]))
	header := traceEventV2Header{
		version:   binary.LittleEndian.Uint16(rawSample[0:2]),
		eventType: binary.LittleEndian.Uint16(rawSample[2:4]),
		flags:     binary.LittleEndian.Uint16(rawSample[4:6]),
		pid:       binary.LittleEndian.Uint32(rawSample[12:16]),
		tid:       binary.LittleEndian.Uint32(rawSample[16:20]),
		sysID:     binary.LittleEndian.Uint32(rawSample[20:24]),
		tsNs:      binary.LittleEndian.Uint64(rawSample[32:40]),
	}
	return header, rawSample[headerLen:size], true
}

func decodeTraceEventV2EnterEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	if len(body) < traceEventV2EnterBodyLen {
		return traceEventEnvelope{}, false
	}
	ret := int64(binary.LittleEndian.Uint64(body[0:8]))
	probeRetEnter := int32(binary.LittleEndian.Uint32(body[8:12]))
	probeRetExit := int32(binary.LittleEndian.Uint32(body[12:16]))
	args := traceEventV2Args(body[16:64])
	captureLen := binary.LittleEndian.Uint32(body[64:68])
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
	scMeta := syscallMeta(header.sysID)
	sections := copyPayloadSections(payloadSectionsForRawPayloadEvent(raw, scMeta))
	return traceEventEnvelope{
		valid:         true,
		eventVersion:  header.version,
		pid:           header.pid,
		tid:           header.tid,
		sysID:         header.sysID,
		eventType:     header.eventType,
		eventFlags:    eventFlags,
		enterTime:     header.tsNs,
		args:          args,
		ret:           ret,
		ptr:           primarySyscallPointer(scMeta, args, sections),
		probeRetEnter: probeRetEnter,
		probeRetExit:  probeRetExit,
		payload:       sections,
	}, true
}

func decodeTraceEventV2ExitEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	if len(body) < traceEventV2ExitBodyLen {
		return traceEventEnvelope{}, false
	}
	ret := int64(binary.LittleEndian.Uint64(body[0:8]))
	duration := binary.LittleEndian.Uint64(body[8:16])
	args := traceEventV2Args(body[16:64])
	captureLen := binary.LittleEndian.Uint32(body[64:68])
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
	scMeta := syscallMeta(header.sysID)
	sections := copyPayloadSections(payloadSectionsForRawPayloadEvent(raw, scMeta))
	return traceEventEnvelope{
		valid:        true,
		eventVersion: header.version,
		pid:          header.pid,
		tid:          header.tid,
		sysID:        header.sysID,
		eventType:    header.eventType,
		eventFlags:   eventFlags,
		enterTime:    traceEventV2EnterTime(header.tsNs, duration),
		args:         args,
		ret:          ret,
		duration:     duration,
		ptr:          primarySyscallPointer(scMeta, args, sections),
		payload:      sections,
	}, true
}

func decodeTraceEventV2LifecycleEnvelope(header traceEventV2Header, body []byte) (traceEventEnvelope, bool) {
	if len(body) < traceEventV2LifecycleBodyLen {
		return traceEventEnvelope{}, false
	}
	action := binary.LittleEndian.Uint32(body[0:4])
	captureLen := binary.LittleEndian.Uint32(body[4:8])
	args := traceEventV2Args(body[8:56])
	payload, ok := traceEventV2Payload(body, traceEventV2LifecycleBodyLen, captureLen)
	if !ok {
		return traceEventEnvelope{}, false
	}
	return traceEventEnvelope{
		valid:           true,
		eventVersion:    header.version,
		pid:             header.pid,
		tid:             header.tid,
		eventType:       header.eventType,
		eventFlags:      traceEventV2EventFlags(header, payload),
		lifecycleAction: action,
		enterTime:       header.tsNs,
		args:            args,
		snapshotText:    lifecycleSnapshotString(payload),
	}, true
}

func traceEventV2Args(data []byte) [6]uint64 {
	var args [6]uint64
	for i := range args {
		args[i] = binary.LittleEndian.Uint64(data[i*8 : i*8+8])
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
