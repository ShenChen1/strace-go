package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	capHeaderSize = 8
	capDataSize   = 12

	linuxCapabilityVersion1 = 0x19980330
	linuxCapabilityVersion2 = 0x20071026
	linuxCapabilityVersion3 = 0x20080522
)

var capabilityNames = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

func registerBuiltinCapability(r *Registry) {
	h := &CapabilityHandler{}
	r.Register("capget", h)
	r.Register("capset", h)
}

type CapabilityHandler struct {
	DefaultHandler
}

type capHeader struct {
	version uint32
	pid     int32
}

func (h *CapabilityHandler) Handle(ctx *Context) Result {
	if ctx.Opts != nil && ctx.Opts.VerboseDisabled[ctx.ScMeta.Name] {
		return h.handleRaw(ctx)
	}

	header, headerText, headerOK := h.decodeHeader(ctx)
	dataText := h.decodeData(ctx, header, headerOK)
	return Result{ArgParts: []string{headerText, dataText}}
}

func (h *CapabilityHandler) handleRaw(ctx *Context) Result {
	return Result{ArgParts: []string{formatNullablePointer(ctx.Args[0]), formatNullablePointer(ctx.Args[1])}}
}

func (h *CapabilityHandler) decodeHeader(ctx *Context) (capHeader, string, bool) {
	if ctx.Args[0] == 0 {
		return capHeader{}, "NULL", false
	}
	if ctx.ArgProbeRet(0) != 0 {
		return capHeader{}, fmt.Sprintf("%#x", ctx.Args[0]), false
	}
	data, ok := capBPFSegment(ctx, 0, PayloadDirectionIn, capHeaderSize)
	if !ok {
		return capHeader{}, fmt.Sprintf("%#x", ctx.Args[0]), false
	}
	header := capHeader{
		version: binary.LittleEndian.Uint32(data[0:4]),
		pid:     int32(binary.LittleEndian.Uint32(data[4:8])),
	}
	return header, fmt.Sprintf("{version=%s, pid=%d}", formatCapabilityVersion(header.version), header.pid), true
}

func (h *CapabilityHandler) decodeData(ctx *Context, header capHeader, headerOK bool) string {
	if ctx.Args[1] == 0 {
		return "NULL"
	}
	words, knownVersion := capabilityVersionWords(header.version)
	if !headerOK || !knownVersion {
		return fmt.Sprintf("%#x", ctx.Args[1])
	}

	isExit := ctx.ScMeta.Name == "capget"
	direction := PayloadDirectionIn
	if isExit {
		direction = PayloadDirectionOut
	}
	size := words * capDataSize
	data, ok := capBPFSegment(ctx, 1, direction, size)
	if !ok {
		return fmt.Sprintf("%#x", ctx.Args[1])
	}
	return formatCapabilityData(data, words)
}

func capBPFSegment(
	ctx *Context,
	argIndex int,
	direction PayloadDirection,
	size int,
) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(argIndex, direction); ok && len(data) >= size {
		return data[:size], true
	}
	return nil, false
}

func formatNullablePointer(ptr uint64) string {
	if ptr == 0 {
		return "NULL"
	}
	return fmt.Sprintf("%#x", ptr)
}

func formatCapabilityVersion(version uint32) string {
	switch version {
	case linuxCapabilityVersion1:
		return "_LINUX_CAPABILITY_VERSION_1"
	case linuxCapabilityVersion2:
		return "_LINUX_CAPABILITY_VERSION_2"
	case linuxCapabilityVersion3:
		return "_LINUX_CAPABILITY_VERSION_3"
	default:
		return fmt.Sprintf("%#x /* _LINUX_CAPABILITY_VERSION_??? */", version)
	}
}

func capabilityVersionWords(version uint32) (int, bool) {
	switch version {
	case linuxCapabilityVersion1:
		return 1, true
	case linuxCapabilityVersion2, linuxCapabilityVersion3:
		return 2, true
	default:
		return 0, false
	}
}

func formatCapabilityData(data []byte, words int) string {
	return fmt.Sprintf("{effective=%s, permitted=%s, inheritable=%s}",
		formatCapabilitySet(capDataValue(data, words, 0)),
		formatCapabilitySet(capDataValue(data, words, 1)),
		formatCapabilitySet(capDataValue(data, words, 2)))
}

func capDataValue(data []byte, words int, field int) uint64 {
	var value uint64
	for word := 0; word < words; word++ {
		offset := word*capDataSize + field*4
		value |= uint64(binary.LittleEndian.Uint32(data[offset:offset+4])) << (32 * word)
	}
	return value
}

func formatCapabilitySet(value uint64) string {
	if value == 0 {
		return "0"
	}

	parts := make([]string, 0)
	var knownMask uint64
	for bit, name := range capabilityNames {
		mask := uint64(1) << bit
		knownMask |= mask
		if value&mask != 0 {
			parts = append(parts, "1<<"+name)
		}
	}
	if unknown := value &^ knownMask; unknown != 0 {
		parts = append(parts, fmt.Sprintf("%#x", unknown))
	}
	return strings.Join(parts, "|")
}
