package main

type payloadSource interface {
	Arg(index int) (uint64, bool)
	PayloadWindow(offset int, maxLen int) ([]byte, bool)
}

// rawPayloadEvent is the narrow record view required by payload projection.
type rawPayloadEvent struct {
	valid         bool
	args          [6]uint64
	eventType     uint16
	eventFlags    uint32
	ret           int64
	probeRetEnter int32
	probeRetExit  int32
	data          []byte
}

type windowPayloadSource struct {
	args [6]uint64
	data []byte
}

type payloadSourceWindow struct {
	offset int
	data   []byte
}

type sectionPayloadSource struct {
	args    [6]uint64
	windows []payloadSourceWindow
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

func newFixedEventPayloadSource(eventRaw *bpfEvent) windowPayloadSource {
	return newFixedPayloadSourceFromRaw(newRawPayloadEventFromBPF(eventRaw))
}

func newFixedPayloadSourceFromRaw(raw rawPayloadEvent) windowPayloadSource {
	if !raw.valid {
		return windowPayloadSource{}
	}
	return windowPayloadSource{
		args: raw.args,
		data: raw.data,
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

func newFixedPayloadEvent(eventRaw *bpfEvent) payloadEvent {
	return newFixedPayloadEventFromRaw(newRawPayloadEventFromBPF(eventRaw))
}

func newFixedPayloadEventFromRaw(raw rawPayloadEvent) payloadEvent {
	if !raw.valid {
		return payloadEvent{}
	}
	return payloadEvent{
		source: newFixedPayloadSourceFromRaw(raw),
		meta: payloadEventMeta{
			valid:         true,
			eventType:     raw.eventType,
			ret:           raw.ret,
			probeRetEnter: raw.probeRetEnter,
			probeRetExit:  raw.probeRetExit,
		},
	}
}

func newSectionPayloadSource(args [6]uint64, windows []payloadSourceWindow) sectionPayloadSource {
	source := sectionPayloadSource{
		args:    args,
		windows: make([]payloadSourceWindow, 0, len(windows)),
	}
	for _, window := range windows {
		if window.offset < 0 || len(window.data) == 0 {
			continue
		}
		source.windows = append(source.windows, window)
	}
	return source
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

func (s windowPayloadSource) Arg(index int) (uint64, bool) {
	if index < 0 || index >= len(s.args) {
		return 0, false
	}
	return s.args[index], true
}

func (s windowPayloadSource) PayloadWindow(offset int, maxLen int) ([]byte, bool) {
	if offset < 0 || maxLen <= 0 || len(s.data) == 0 {
		return nil, false
	}
	if offset >= len(s.data) {
		return nil, false
	}
	end := len(s.data)
	if limit := offset + maxLen; limit < end {
		end = limit
	}
	if end <= offset {
		return nil, false
	}
	return s.data[offset:end], true
}

func (s sectionPayloadSource) Arg(index int) (uint64, bool) {
	if index < 0 || index >= len(s.args) {
		return 0, false
	}
	return s.args[index], true
}

func (s sectionPayloadSource) PayloadWindow(offset int, maxLen int) ([]byte, bool) {
	if offset < 0 || maxLen <= 0 {
		return nil, false
	}
	for _, window := range s.windows {
		rel := offset - window.offset
		if rel < 0 || rel >= len(window.data) {
			continue
		}
		end := rel + maxLen
		if end > len(window.data) {
			end = len(window.data)
		}
		if end <= rel {
			return nil, false
		}
		return window.data[rel:end], true
	}
	return nil, false
}
