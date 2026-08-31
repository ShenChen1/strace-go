package main

import (
	"encoding/binary"
	"fmt"

	"strace-go/pkg/handler"
)

const (
	pidNamespaceTIDOffset  = 0
	pidNamespaceTGIDOffset = 4
)

func pidNamespaceReturnComment(syscallName string, ret int64, ctx *handler.Context) string {
	if ret <= 0 || ctx == nil {
		return ""
	}
	data, ok := pidNamespaceSnapshotData(ctx.PayloadSections)
	if !ok {
		return ""
	}
	var translated uint32
	switch syscallName {
	case "getpid":
		translated = binary.LittleEndian.Uint32(data[pidNamespaceTGIDOffset:])
	case "gettid":
		translated = binary.LittleEndian.Uint32(data[pidNamespaceTIDOffset:])
	default:
		return ""
	}
	if translated == 0 || int64(translated) == ret {
		return ""
	}
	return fmt.Sprintf(" /* %d in strace's PID NS */", translated)
}

func pidNamespaceSnapshotData(sections []handler.PayloadSection) ([]byte, bool) {
	for _, section := range sections {
		if section.Kind != handler.PayloadKindPIDNamespace ||
			section.Direction != handler.PayloadDirectionOut ||
			section.ArgIndex != payloadTLVPIDNamespaceArgIndex ||
			section.ProbeRet != 0 || section.CopiedLen != pidNamespaceSnapshotSize ||
			len(section.Data) != pidNamespaceSnapshotSize {
			continue
		}
		return section.Data, true
	}
	return nil, false
}
