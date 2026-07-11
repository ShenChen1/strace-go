package main

type payloadSource interface {
	Arg(index int) (uint64, bool)
	PayloadWindow(offset int, maxLen int) ([]byte, bool)
}

type fixedEventPayloadSource struct {
	eventRaw *bpfEvent
}

// payloadEventMeta is the event header subset payload rules need.
type payloadEventMeta struct {
	valid         bool
	eventType     uint16
	ret           int64
	probeRetEnter int32
	probeRetExit  int32
}

type payloadEvent struct {
	raw    *bpfEvent
	source payloadSource
	meta   payloadEventMeta
}

func newFixedEventPayloadSource(eventRaw *bpfEvent) fixedEventPayloadSource {
	return fixedEventPayloadSource{eventRaw: eventRaw}
}

func newFixedPayloadEvent(eventRaw *bpfEvent) payloadEvent {
	return payloadEvent{
		raw:    eventRaw,
		source: newFixedEventPayloadSource(eventRaw),
		meta: payloadEventMeta{
			valid:         true,
			eventType:     eventRaw.EventType,
			ret:           eventRaw.Ret,
			probeRetEnter: eventRaw.ProbeRetEnter,
			probeRetExit:  eventRaw.ProbeRetExit,
		},
	}
}

func (e payloadEvent) Arg(index int) uint64 {
	if e.source == nil {
		return 0
	}
	if value, ok := e.source.Arg(index); ok {
		return value
	}
	return 0
}

func (e payloadEvent) Ret() int64 {
	if !e.meta.valid && e.raw != nil {
		return e.raw.Ret
	}
	return e.meta.ret
}

func (e payloadEvent) IsExit() bool {
	if !e.meta.valid && e.raw != nil {
		return isExitEvent(e.raw)
	}
	return e.meta.eventType == bpfEventTypeExit
}

func (e payloadEvent) ProbeRetEnterArg(index int) int32 {
	if !e.meta.valid && e.raw != nil {
		return getArgProbeStatus(e.raw.ProbeRetEnter, index)
	}
	return getArgProbeStatus(e.meta.probeRetEnter, index)
}

func (e payloadEvent) ProbeRetEnter() int32 {
	if !e.meta.valid && e.raw != nil {
		return e.raw.ProbeRetEnter
	}
	return e.meta.probeRetEnter
}

func (e payloadEvent) ProbeRetExit() int32 {
	if !e.meta.valid && e.raw != nil {
		return e.raw.ProbeRetExit
	}
	return e.meta.probeRetExit
}

func (e payloadEvent) IsSyscallEvent() bool {
	if !e.meta.valid && e.raw != nil {
		return e.raw.EventType == bpfEventTypeEnter || e.raw.EventType == bpfEventTypeExit
	}
	if !e.meta.valid {
		return true
	}
	return e.meta.eventType == bpfEventTypeEnter || e.meta.eventType == bpfEventTypeExit
}

func (s fixedEventPayloadSource) Arg(index int) (uint64, bool) {
	if s.eventRaw == nil || index < 0 || index >= len(s.eventRaw.Args) {
		return 0, false
	}
	return s.eventRaw.Args[index], true
}

func (s fixedEventPayloadSource) PayloadWindow(offset int, maxLen int) ([]byte, bool) {
	if s.eventRaw == nil || offset < 0 || maxLen <= 0 || s.eventRaw.DataLen == 0 {
		return nil, false
	}
	if uint32(offset) >= s.eventRaw.DataLen || offset >= len(s.eventRaw.StrArg) {
		return nil, false
	}
	end := int(s.eventRaw.DataLen)
	if end > len(s.eventRaw.StrArg) {
		end = len(s.eventRaw.StrArg)
	}
	if limit := offset + maxLen; limit < end {
		end = limit
	}
	if end <= offset {
		return nil, false
	}
	return s.eventRaw.StrArg[offset:end], true
}
