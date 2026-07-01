package main

import (
	"bytes"

	"strace-go/pkg/handler"
)

const (
	pathPayloadPrimaryOffset   = 0
	pathPayloadSecondaryOffset = 512
	pathPayloadMaxBytes        = 512
)

type pathPayloadSpec struct {
	argIndex int
	offset   int
}

func simplePathPayloadArgIndex(scName string) (int, bool) {
	switch scName {
	case "open", "creat", "access", "chdir", "chroot", "chmod", "chown", "lchown",
		"mkdir", "mknod", "rmdir", "unlink", "swapon", "swapoff", "acct", "truncate", "fsopen":
		return 0, true
	case "openat", "mkdirat", "mknodat", "chmodat", "fchmodat", "faccessat", "faccessat2",
		"unlinkat", "fchownat", "fspick":
		return 1, true
	default:
		return 0, false
	}
}

func dualPathPayloadSectionsForEvent(eventRaw *bpfEvent, firstArg int, secondArg int) []handler.PayloadSection {
	sections := stringPayloadSectionFromWindowAt(eventRaw, pathPayloadSpec{
		argIndex: firstArg,
		offset:   pathPayloadPrimaryOffset,
	})
	return append(sections, stringPayloadSectionFromWindowAt(eventRaw, pathPayloadSpec{
		argIndex: secondArg,
		offset:   pathPayloadSecondaryOffset,
	})...)
}

func stringPayloadSectionFromWindowAt(eventRaw *bpfEvent, spec pathPayloadSpec) []handler.PayloadSection {
	data, ok := eventPayloadWindow(eventRaw, spec.offset, pathPayloadMaxBytes)
	if !ok {
		return nil
	}
	if nul := bytes.IndexByte(data, 0); nul >= 0 {
		data = data[:nul+1]
	}
	section := newPayloadSection(eventRaw, payloadWindowSpec{
		kind:      handler.PayloadKindString,
		direction: handler.PayloadDirectionIn,
		argIndex:  spec.argIndex,
		offset:    spec.offset,
		userLen:   uint32(len(data)),
		probeRet:  getArgProbeStatus(eventRaw.ProbeRetEnter, spec.argIndex),
	}, data)
	return []handler.PayloadSection{section}
}
