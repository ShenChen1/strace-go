package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/handler"
)

const (
	cloneNewTime       = uint64(0x00000080)
	cloneNewNS         = uint64(0x00020000)
	cloneNewCgroup     = uint64(0x02000000)
	cloneNewUTS        = uint64(0x04000000)
	cloneNewIPC        = uint64(0x08000000)
	cloneNewUser       = uint64(0x10000000)
	cloneNewPID        = uint64(0x20000000)
	cloneNewNet        = uint64(0x40000000)
	cloneIntoCgroup    = uint64(0x200000000)
	namespaceFlagBytes = 8
)

type namespaceField struct {
	flags  uint64
	name   string
	offset int
}

var namespaceFields = [...]namespaceField{
	{flags: cloneNewCgroup | cloneIntoCgroup, name: "cgroup", offset: 8},
	{flags: cloneNewIPC, name: "ipc", offset: 12},
	{flags: cloneNewNS, name: "mnt", offset: 16},
	{flags: cloneNewNet, name: "net", offset: 20},
	{flags: cloneNewPID, name: "pid", offset: 24},
	{flags: cloneNewTime, name: "time", offset: 28},
	{flags: cloneNewUTS, name: "uts", offset: 32},
	{flags: cloneNewUser, name: "user", offset: 36},
}

func decorateNamespaceResult(result handler.Result, ctx *handler.Context) handler.Result {
	description := namespaceReturnDescription(ctx)
	if description == "" {
		return result
	}
	if result.ReturnDesc == "" {
		result.ReturnDesc = description
	} else {
		result.ReturnDesc += ", " + description
	}
	return result
}

func namespaceReturnDescription(ctx *handler.Context) string {
	if ctx == nil || ctx.Ret < 0 {
		return ""
	}
	data, ok := namespaceSnapshotData(ctx.PayloadSections)
	if !ok {
		return ""
	}
	flags := binary.LittleEndian.Uint64(data[:namespaceFlagBytes])
	parts := make([]string, 0, len(namespaceFields))
	for _, field := range namespaceFields {
		if flags&field.flags == 0 {
			continue
		}
		id := binary.LittleEndian.Uint32(data[field.offset : field.offset+4])
		if id != 0 {
			parts = append(parts, fmt.Sprintf("%s:[%d]", field.name, id))
		}
	}
	return strings.Join(parts, ", ")
}

func namespaceSnapshotData(sections []handler.PayloadSection) ([]byte, bool) {
	for _, section := range sections {
		if section.Kind != handler.PayloadKindNamespace ||
			section.Direction != handler.PayloadDirectionOut ||
			section.ArgIndex != payloadTLVNamespaceArgIndex ||
			section.ProbeRet != 0 || section.CopiedLen != namespaceSnapshotSize ||
			len(section.Data) != namespaceSnapshotSize {
			continue
		}
		return section.Data, true
	}
	return nil, false
}
