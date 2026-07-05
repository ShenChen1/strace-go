package main

type payloadSource interface {
	Arg(index int) (uint64, bool)
	PayloadWindow(offset int, maxLen int) ([]byte, bool)
}

type fixedEventPayloadSource struct {
	eventRaw *bpfEvent
}

type payloadEvent struct {
	raw    *bpfEvent
	source payloadSource
}

func newFixedEventPayloadSource(eventRaw *bpfEvent) fixedEventPayloadSource {
	return fixedEventPayloadSource{eventRaw: eventRaw}
}

func newFixedPayloadEvent(eventRaw *bpfEvent) payloadEvent {
	return payloadEvent{
		raw:    eventRaw,
		source: newFixedEventPayloadSource(eventRaw),
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
	if e.raw == nil {
		return 0
	}
	return e.raw.Ret
}

func (e payloadEvent) IsExit() bool {
	return e.raw != nil && isExitEvent(e.raw)
}

func (e payloadEvent) ProbeRetEnterArg(index int) int32 {
	if e.raw == nil {
		return 0
	}
	return getArgProbeStatus(e.raw.ProbeRetEnter, index)
}

func (e payloadEvent) ProbeRetExit() int32 {
	if e.raw == nil {
		return 0
	}
	return e.raw.ProbeRetExit
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
