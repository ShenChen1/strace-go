package main

type payloadSource interface {
	Arg(index int) (uint64, bool)
	PayloadWindow(offset int, maxLen int) ([]byte, bool)
}

type fixedEventPayloadSource struct {
	eventRaw *bpfEvent
}

func newFixedEventPayloadSource(eventRaw *bpfEvent) fixedEventPayloadSource {
	return fixedEventPayloadSource{eventRaw: eventRaw}
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
