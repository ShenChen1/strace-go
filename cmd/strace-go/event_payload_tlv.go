package main

import (
	"encoding/binary"

	"strace-go/pkg/handler"
)

func payloadTLVSectionsForRawInto(
	raw rawPayloadEvent,
	dst *[]handler.PayloadSection,
) ([]handler.PayloadSection, bool) {
	if dst != nil {
		*dst = (*dst)[:0]
	}
	if !raw.valid || raw.eventFlags&bpfEventFlagPayloadTLV == 0 {
		return nil, false
	}
	sections, ok := decodePayloadTLVSectionsInto(raw.data, dst)
	if !ok {
		if dst != nil {
			*dst = (*dst)[:0]
		}
		return nil, true
	}
	return sections, true
}

func decodePayloadTLVSectionsInto(
	data []byte,
	dst *[]handler.PayloadSection,
) ([]handler.PayloadSection, bool) {
	var sections []handler.PayloadSection
	if dst == nil {
		sections = make([]handler.PayloadSection, 0, 4)
	} else {
		sections = (*dst)[:0]
	}
	for len(data) > 0 {
		if len(data) < payloadTLVHeaderSize {
			if dst != nil {
				*dst = sections
			}
			return nil, false
		}
		section, next, ok := decodePayloadTLVSection(data)
		if !ok {
			if dst != nil {
				*dst = sections
			}
			return nil, false
		}
		sections = append(sections, section)
		data = next
	}
	if dst != nil {
		*dst = sections
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
	case payloadTLVKindCmsg:
		return handler.PayloadKindCmsg, true
	case payloadTLVKindFDState:
		return handler.PayloadKindFDState, true
	case payloadTLVKindFDPath:
		return handler.PayloadKindFDPath, true
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
