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

func keyPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	sections := keyStringPayloadSection(event, 0, keyTypePayloadOffset, keyTypePayloadMaxBytes)
	sections = append(sections, keyStringPayloadSection(event, 1, keyDescriptionPayloadOffset, keyDescriptionPayloadMax)...)
	switch scName {
	case "add_key":
		sections = append(sections, keyBytesPayloadSection(event, 2)...)
	case "request_key":
		sections = append(sections, keyStringPayloadSection(event, 2, keyDataPayloadOffset, keyDataPayloadMaxBytes)...)
	}
	return sections
}

func keyStringPayloadSection(event payloadEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	if event.Arg(argIndex) == 0 {
		return nil
	}
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: argIndex,
		offset:   offset,
		maxBytes: maxLen,
	})
}

func keyBytesPayloadSection(event payloadEvent, argIndex int) []handler.PayloadSection {
	if event.Arg(argIndex) == 0 || event.Arg(3) == 0 {
		return nil
	}
	userLen := uint32Clamped(event.Arg(3))
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    keyDataPayloadOffset,
		userLen:   userLen,
		maxLen:    keyDataPayloadMaxBytes,
		probeRet:  event.ProbeRetEnterArg(argIndex),
	})
}
