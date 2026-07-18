package main

import "bytes"

func newRawEventEnvelopeFromBPF(eventRaw *bpfEvent) rawEventEnvelope {
	if eventRaw == nil {
		return rawEventEnvelope{}
	}
	payloadEvent := newRawPayloadEventFromBPF(eventRaw)
	snapshotText := ""
	if eventRaw.EventType == bpfEventTypeLifecycle && eventRaw.LifecycleAction == lifecycleExec {
		snapshotText = lifecycleSnapshotString(payloadEvent.data)
	}
	return rawEventEnvelope{
		valid:           true,
		eventVersion:    eventRaw.EventVersion,
		pid:             eventRaw.Pid,
		tid:             eventRaw.Tid,
		sysID:           eventRaw.SysId,
		eventType:       eventRaw.EventType,
		eventFlags:      eventRaw.EventFlags,
		lifecycleAction: eventRaw.LifecycleAction,
		enterTime:       eventRaw.EnterTime,
		args:            eventRaw.Args,
		ret:             eventRaw.Ret,
		duration:        eventRaw.Duration,
		ptr:             eventRaw.Ptr,
		stackID:         eventRaw.StackId,
		probeRetEnter:   eventRaw.ProbeRetEnter,
		probeRetExit:    eventRaw.ProbeRetExit,
		snapshotText:    snapshotText,
		payload:         copyPayloadSections(payloadSectionsForRawPayloadEvent(payloadEvent, syscallMeta(eventRaw.SysId))),
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
