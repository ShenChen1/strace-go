package main

import (
	"encoding/binary"

	"strace-go/pkg/handler"
)

const (
	execPayloadSnapshotMagic      = 0x45584543
	execPayloadSnapshotOffset     = 4096
	execPayloadSnapshotHeaderSize = 32
	execPayloadArgSnapshotSize    = 56
	execPayloadArgSnapshotCount   = 48
	execPayloadEnvSnapshotCount   = 64
	execPayloadSnapshotSize       = execPayloadSnapshotHeaderSize +
		execPayloadArgSnapshotCount*execPayloadArgSnapshotSize +
		execPayloadEnvSnapshotCount*execPayloadArgSnapshotSize
)

func execPayloadSectionsFromSource(event payloadEvent, scName string) []handler.PayloadSection {
	argvIndex, ok := execArgvIndex(scName)
	if !ok {
		return nil
	}
	if event.source == nil {
		return nil
	}
	data, ok := event.source.PayloadWindow(execPayloadSnapshotOffset, execPayloadSnapshotSize)
	if !ok || len(data) < execPayloadSnapshotHeaderSize {
		return nil
	}
	if binary.LittleEndian.Uint32(data[0:4]) != execPayloadSnapshotMagic {
		return nil
	}
	section := newPayloadSectionFromSource(event.source, payloadWindowSpec{
		kind:      handler.PayloadKindExecArgs,
		direction: handler.PayloadDirectionIn,
		argIndex:  argvIndex,
		offset:    execPayloadSnapshotOffset,
		userLen:   uint32(execPayloadSnapshotSize),
		probeRet:  0,
	}, data)
	return []handler.PayloadSection{section}
}

func execArgvIndex(scName string) (int, bool) {
	switch scName {
	case "execve":
		return 1, true
	case "execveat":
		return 2, true
	default:
		return 0, false
	}
}
