package main

import "strace-go/pkg/handler"

const (
	fsconfigKeyOffset     = 0
	fsconfigKeyMaxBytes   = 257
	fsconfigValueOffset   = 257
	fsconfigValueMaxBytes = 4096
	mountSourceOffset     = 0
	mountTargetOffset     = 512
	mountTypeOffset       = handler.BpfExitArgOffset
	mountTypeMaxBytes     = 128
	mountDataOffset       = 1152
	mountStringMaxBytes   = 512
)

func fsPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "mount":
		return mountPayloadSectionsFromSource(event)
	case "umount2":
		return fsStringPayloadSection(event, 0, mountSourceOffset, mountStringMaxBytes)
	case "fsconfig":
		return fsconfigPayloadSectionsFromSource(event)
	default:
		return nil
	}
}

func mountPayloadSectionsFromSource(event payloadEvent) []handler.PayloadSection {
	sections := fsStringPayloadSection(event, 0, mountSourceOffset, mountStringMaxBytes)
	sections = append(sections, fsStringPayloadSection(event, 1, mountTargetOffset, mountStringMaxBytes)...)
	sections = append(sections, fsStringPayloadSection(event, 2, mountTypeOffset, mountTypeMaxBytes)...)
	return append(sections, fsStringPayloadSection(event, 4, mountDataOffset, mountStringMaxBytes)...)
}

func fsconfigPayloadSectionsFromSource(event payloadEvent) []handler.PayloadSection {
	sections := fsStringPayloadSection(event, 2, fsconfigKeyOffset, fsconfigKeyMaxBytes)
	if event.Arg(1) == 2 {
		return append(sections, fsconfigBytesPayloadSection(event)...)
	}
	return append(sections, fsStringPayloadSection(event, 3, fsconfigValueOffset, fsconfigValueMaxBytes)...)
}

func fsconfigBytesPayloadSection(event payloadEvent) []handler.PayloadSection {
	userLen := uint32Clamped(event.Arg(4) & 0x1fff)
	return payloadSectionFromSourceSpec(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  3,
		offset:    fsconfigValueOffset,
		userLen:   userLen,
		maxLen:    fsconfigValueMaxBytes,
		probeRet:  event.ProbeRetEnterArg(3),
	})
}

func fsStringPayloadSection(event payloadEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	if event.Arg(argIndex) == 0 {
		return nil
	}
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: argIndex,
		offset:   offset,
		maxBytes: maxLen,
	})
}
