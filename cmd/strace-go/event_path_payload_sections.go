package main

import "strace-go/pkg/handler"

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

func dualPathPayloadSectionsFromSource(event payloadEvent, firstArg int, secondArg int) []handler.PayloadSection {
	sections := stringPayloadSectionFromSourceAt(event, pathPayloadSpec{
		argIndex: firstArg,
		offset:   pathPayloadPrimaryOffset,
	})
	return append(sections, stringPayloadSectionFromSourceAt(event, pathPayloadSpec{
		argIndex: secondArg,
		offset:   pathPayloadSecondaryOffset,
	})...)
}

func stringPayloadSectionFromSourceAt(event payloadEvent, spec pathPayloadSpec) []handler.PayloadSection {
	return stringPayloadSectionFromSourceSpec(event, stringPayloadWindowSpec{
		argIndex: spec.argIndex,
		offset:   spec.offset,
		maxBytes: pathPayloadMaxBytes,
	})
}

func stringPayloadSectionFromWindowAt(eventRaw *bpfEvent, spec pathPayloadSpec) []handler.PayloadSection {
	return stringPayloadSectionFromSourceAt(newFixedPayloadEvent(eventRaw), spec)
}
