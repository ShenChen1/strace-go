package main

import (
	"encoding/binary"

	"strace-go/pkg/handler"
)

const (
	payloadTLVHeaderSize       = 32
	payloadTLVKindString       = 1
	payloadTLVKindBytes        = 2
	payloadTLVKindStruct       = 3
	payloadTLVKindIovec        = 4
	payloadTLVKindSockaddr     = 5
	payloadTLVKindExecArgs     = 6
	payloadTLVFlagDirectionOut = 1
)

func payloadTLVSectionsForRaw(raw rawPayloadEvent) ([]handler.PayloadSection, bool) {
	if !raw.valid || raw.eventFlags&bpfEventFlagPayloadTLV == 0 {
		return nil, false
	}
	sections, ok := decodePayloadTLVSections(raw.data)
	if !ok {
		return nil, true
	}
	return sections, true
}

func decodePayloadTLVSections(data []byte) ([]handler.PayloadSection, bool) {
	sections := make([]handler.PayloadSection, 0, 4)
	for len(data) > 0 {
		if len(data) < payloadTLVHeaderSize {
			return nil, false
		}
		section, next, ok := decodePayloadTLVSection(data)
		if !ok {
			return nil, false
		}
		sections = append(sections, section)
		data = next
	}
	return sections, true
}

func decodePayloadTLVSection(data []byte) (handler.PayloadSection, []byte, bool) {
	kind, ok := payloadKindFromTLV(binary.LittleEndian.Uint16(data[0:2]))
	if !ok {
		return handler.PayloadSection{}, nil, false
	}
	copiedLen := binary.LittleEndian.Uint32(data[12:16])
	if copiedLen > uint32(len(data)-payloadTLVHeaderSize) {
		return handler.PayloadSection{}, nil, false
	}
	totalLen := payloadTLVHeaderSize + int(copiedLen)
	section := handler.PayloadSection{
		Kind:      kind,
		Direction: payloadDirectionFromTLV(binary.LittleEndian.Uint16(data[4:6])),
		ArgIndex:  int(binary.LittleEndian.Uint16(data[2:4])),
		UserLen:   binary.LittleEndian.Uint32(data[8:12]),
		CopiedLen: copiedLen,
		ProbeRet:  int32(binary.LittleEndian.Uint32(data[16:20])),
		UserPtr:   binary.LittleEndian.Uint64(data[24:32]),
		Data:      data[payloadTLVHeaderSize:totalLen],
	}
	return section, data[totalLen:], true
}

func payloadKindFromTLV(kind uint16) (handler.PayloadKind, bool) {
	switch kind {
	case payloadTLVKindString:
		return handler.PayloadKindString, true
	case payloadTLVKindBytes:
		return handler.PayloadKindBytes, true
	case payloadTLVKindStruct:
		return handler.PayloadKindStruct, true
	case payloadTLVKindIovec:
		return handler.PayloadKindIovec, true
	case payloadTLVKindSockaddr:
		return handler.PayloadKindSockaddr, true
	case payloadTLVKindExecArgs:
		return handler.PayloadKindExecArgs, true
	default:
		return "", false
	}
}

func payloadDirectionFromTLV(flags uint16) handler.PayloadDirection {
	if flags&payloadTLVFlagDirectionOut != 0 {
		return handler.PayloadDirectionOut
	}
	return handler.PayloadDirectionIn
}
