package main

import "strace-go/pkg/handler"

const (
	keyTypePayloadOffset        = 0
	keyTypePayloadMaxBytes      = 64
	keyDescriptionPayloadOffset = 64
	keyDescriptionPayloadMax    = 128
	keyDataPayloadOffset        = 256
	keyDataPayloadMaxBytes      = 256
)

func keyPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	sections := keyStringPayloadSection(eventRaw, 0, keyTypePayloadOffset, keyTypePayloadMaxBytes)
	sections = append(sections, keyStringPayloadSection(eventRaw, 1, keyDescriptionPayloadOffset, keyDescriptionPayloadMax)...)
	switch scName {
	case "add_key":
		sections = append(sections, keyBytesPayloadSection(eventRaw, 2)...)
	case "request_key":
		sections = append(sections, keyStringPayloadSection(eventRaw, 2, keyDataPayloadOffset, keyDataPayloadMaxBytes)...)
	}
	return sections
}

func keyStringPayloadSection(eventRaw *bpfEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	if eventRaw.Args[argIndex] == 0 {
		return nil
	}
	return fsStringPayloadSection(eventRaw, argIndex, offset, maxLen)
}

func keyBytesPayloadSection(eventRaw *bpfEvent, argIndex int) []handler.PayloadSection {
	if eventRaw.Args[argIndex] == 0 || eventRaw.Args[3] == 0 {
		return nil
	}
	userLen := uint32Clamped(eventRaw.Args[3])
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    keyDataPayloadOffset,
		userLen:   userLen,
		maxLen:    keyDataPayloadMaxBytes,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	})
}
