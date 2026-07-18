package main

func (s *traceSession) handleEvent(eventRaw *bpfEvent) {
	s.handleEnvelope(newRawEventEnvelopeFromBPF(eventRaw))
}
