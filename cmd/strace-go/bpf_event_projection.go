package main

import "bytes"

func newTraceEventEnvelopeFromBPF(eventRaw *bpfEvent) traceEventEnvelope {
	if eventRaw == nil {
		return traceEventEnvelope{}
	}
	payloadEvent := newRawPayloadEventFromBPF(eventRaw)
	scMeta := syscallMeta(eventRaw.SysId)
	sections := copyPayloadSections(payloadSectionsForRawPayloadEvent(payloadEvent, scMeta))
	return traceEventEnvelope{
		valid:         true,
		eventVersion:  eventRaw.EventVersion,
		pid:           eventRaw.Pid,
		tid:           eventRaw.Tid,
		sysID:         eventRaw.SysId,
		eventType:     eventRaw.EventType,
		eventFlags:    eventRaw.EventFlags,
		enterTime:     eventRaw.EnterTime,
		args:          eventRaw.Args,
		ret:           eventRaw.Ret,
		duration:      eventRaw.Duration,
		ptr:           primarySyscallPointer(scMeta, eventRaw.Args, sections),
		stackID:       eventRaw.StackId,
		probeRetEnter: eventRaw.ProbeRetEnter,
		probeRetExit:  eventRaw.ProbeRetExit,
		payload:       sections,
	}
}

func newRawPayloadEventFromBPF(eventRaw *bpfEvent) rawPayloadEvent {
	if eventRaw == nil {
		return rawPayloadEvent{}
	}
	return rawPayloadEvent{
		valid:         true,
		args:          eventRaw.Args,
		eventType:     eventRaw.EventType,
		eventFlags:    eventRaw.EventFlags,
		ret:           eventRaw.Ret,
		probeRetEnter: eventRaw.ProbeRetEnter,
		probeRetExit:  eventRaw.ProbeRetExit,
		data:          eventPayloadDataFromBPF(eventRaw),
	}
}

func eventPayloadDataFromBPF(eventRaw *bpfEvent) []byte {
	if eventRaw == nil {
		return nil
	}
	dataLen := int(eventRaw.DataLen)
	if dataLen > len(eventRaw.StrArg) {
		dataLen = len(eventRaw.StrArg)
	}
	return eventRaw.StrArg[:dataLen]
}

func lifecycleSnapshotString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return string(data)
}
