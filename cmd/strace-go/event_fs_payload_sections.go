package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

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

func fsPayloadSectionsForEvent(eventRaw *bpfEvent, scName string) []handler.PayloadSection {
	switch scName {
	case "mount":
		return mountPayloadSectionsForEvent(eventRaw)
	case "umount2":
		return fsStringPayloadSection(eventRaw, 0, mountSourceOffset, mountStringMaxBytes)
	case "fsconfig":
		return fsconfigPayloadSectionsForEvent(eventRaw)
	default:
		return nil
	}
}

func mountPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := fsStringPayloadSection(eventRaw, 0, mountSourceOffset, mountStringMaxBytes)
	sections = append(sections, fsStringPayloadSection(eventRaw, 1, mountTargetOffset, mountStringMaxBytes)...)
	sections = append(sections, fsStringPayloadSection(eventRaw, 2, mountTypeOffset, mountTypeMaxBytes)...)
	return append(sections, fsStringPayloadSection(eventRaw, 4, mountDataOffset, mountStringMaxBytes)...)
}

func fsconfigPayloadSectionsForEvent(eventRaw *bpfEvent) []handler.PayloadSection {
	sections := fsStringPayloadSection(eventRaw, 2, fsconfigKeyOffset, fsconfigKeyMaxBytes)
	if eventRaw.Args[1] == 2 {
		return append(sections, fsconfigBytesPayloadSection(eventRaw)...)
	}
	return append(sections, fsStringPayloadSection(eventRaw, 3, fsconfigValueOffset, fsconfigValueMaxBytes)...)
}

func fsconfigBytesPayloadSection(eventRaw *bpfEvent) []handler.PayloadSection {
	userLen := uint32Clamped(eventRaw.Args[4] & 0x1fff)
	return payloadSectionFromWindowSpec(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindBytes,
		direction: handler.PayloadDirectionIn,
		argIndex:  3,
		offset:    fsconfigValueOffset,
		userLen:   userLen,
		maxLen:    fsconfigValueMaxBytes,
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, 3),
	})
}

func fsStringPayloadSection(eventRaw *bpfEvent, argIndex int, offset int, maxLen int) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, offset, maxLen)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: handler.PayloadDirectionIn,
		argIndex:  argIndex,
		offset:    offset,
		userLen:   uint32(len(data)),
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, argIndex),
	}, data)
	return []handler.PayloadSection{section}
}
