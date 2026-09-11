package handler

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"strace-go/pkg/format"
)

const (
	// Must match PAYLOAD_TLV_CLONE3_SET_TID_ARG_INDEX in the generated ABI.
	clone3SetTidPayloadArgIndex = 0xfff9
	clone3SetTidMaxEntries      = 32
	clone3KnownArgsSize         = 88
	clone3FlagPIDFD             = 0x00001000
	clone3FlagChildClearTID     = 0x00200000
	clone3FlagParentSetTID      = 0x00100000
	clone3FlagChildSetTID       = 0x01000000
	clone3FlagSetTLS            = 0x00080000
)

func registerBuiltinProcess(r *Registry) {
	r.Register("clone3", &ProcessHandler{})
}

type ProcessHandler struct{}

func (h *ProcessHandler) Handle(ctx *Context) Result {
	res := Result{}
	switch ctx.SysName {
	case "clone3":
		uargs := ctx.Args[0]
		size := uint64(ctx.Args[1])

		if uargs == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else if size < 64 {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", uargs))
		} else {
			res.ArgParts = append(res.ArgParts, h.formatClone3(ctx, uargs, size))
		}
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", size))
	}
	return res
}

func (h *ProcessHandler) formatClone3(ctx *Context, uargs, size uint64) string {
	capLen := int(size)
	if capLen > 256 {
		capLen = 256
	}
	section, ok := clone3ArgsPayloadSection(ctx)
	if !ok {
		return fmt.Sprintf("%#x", uargs)
	}
	data := section.Data
	if len(data) > capLen {
		data = data[:capLen]
	}

	parts := h.decodeCloneArgsCore(ctx, data, size)

	if size >= 80 {
		parts = append(parts, h.decodeCloneArgsSetTid(ctx, data, size)...)
	}
	if size >= 88 {
		cg := h.u64OrZero(data, 80)
		flags := h.u64OrZero(data, 0)
		if cg != 0 || (flags&0x200000000 != 0) { // CLONE_INTO_CGROUP
			parts = append(parts, fmt.Sprintf("cgroup=%d", cg))
		}
	}

	parts = append(parts, h.decodeCloneArgsUnknownTail(section, size)...)
	structStr := "{" + strings.Join(parts, ", ") + "}"
	postStr := h.decodeCloneArgsPost(ctx, data, size)
	if postStr != "" {
		structStr += " => " + postStr
	}
	return structStr
}

func clone3ArgsPayloadSection(ctx *Context) (PayloadSection, bool) {
	if ctx == nil {
		return PayloadSection{}, false
	}
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 0 && section.Kind == PayloadKindStruct &&
			section.Direction == PayloadDirectionIn && section.ProbeRet == 0 &&
			len(section.Data) > 0 {
			return section, true
		}
	}
	return PayloadSection{}, false
}

func (h *ProcessHandler) decodeCloneArgsUnknownTail(section PayloadSection, size uint64) []string {
	if size <= clone3KnownArgsSize {
		return nil
	}

	data := copiedPayloadData(section)
	if len(data) > clone3KnownArgsSize {
		data = data[clone3KnownArgsSize:]
		if lastNonZeroByte(data) >= 0 {
			parts := []string{fmt.Sprintf("/* bytes %d..%d */ %s", clone3KnownArgsSize,
				clone3KnownArgsSize+len(data)-1, format.BufferEscape(data, len(data), len(data), 2))}
			if section.CopiedLen < section.UserLen {
				parts = append(parts, "???")
			}
			return parts
		}
	}
	if section.CopiedLen < section.UserLen {
		return []string{"???"}
	}
	return nil
}

func (h *ProcessHandler) u64OrZero(data []byte, off int) uint64 {
	if len(data) >= off+8 {
		return binary.LittleEndian.Uint64(data[off : off+8])
	}
	return 0
}

func (h *ProcessHandler) decodeCloneArgsCore(ctx *Context, data []byte, size uint64) []string {
	var parts []string
	flags := h.u64OrZero(data, 0)
	if size >= 8 {
		parts = append(parts, "flags="+decodeFlags(ctx, flags, "clone3_flags"))
	}
	if size >= 16 {
		pfd := h.u64OrZero(data, 8)
		if flags&clone3FlagPIDFD != 0 {
			parts = append(parts, formatPtr("pidfd", pfd))
		}
	}
	if size >= 24 {
		ctid := h.u64OrZero(data, 16)
		if flags&(clone3FlagChildSetTID|clone3FlagChildClearTID) != 0 {
			parts = append(parts, formatPtr("child_tid", ctid))
		}
	}
	if size >= 32 {
		ptid := h.u64OrZero(data, 24)
		if flags&clone3FlagParentSetTID != 0 {
			parts = append(parts, formatPtr("parent_tid", ptid))
		}
	}
	if size >= 40 {
		sig := h.u64OrZero(data, 32)
		if sig == 0 {
			parts = append(parts, "exit_signal=0")
		} else {
			parts = append(parts, fmt.Sprintf("exit_signal=%s", decodeCloneArgsExitSignal(ctx, sig)))
		}
	}
	if size >= 48 {
		stack := h.u64OrZero(data, 40)
		parts = append(parts, formatPtr("stack", stack))
	}
	if size >= 56 {
		ssz := h.u64OrZero(data, 48)
		if ssz == 0 {
			parts = append(parts, "stack_size=0")
		} else {
			parts = append(parts, fmt.Sprintf("stack_size=%#x", ssz))
		}
	}
	if size >= 64 {
		tls := h.u64OrZero(data, 56)
		if flags&clone3FlagSetTLS != 0 {
			parts = append(parts, formatPtr("tls", tls))
		}
	}
	return parts
}

func decodeCloneArgsExitSignal(ctx *Context, signal uint64) string {
	table, ok := xlatTable(ctx, "signalnames")
	if ok {
		for _, entry := range table.Entries {
			if entry.Val == signal {
				return decodeFlags(ctx, signal, "signalnames")
			}
		}
	}
	return strconv.FormatUint(signal, 10)
}

func (h *ProcessHandler) decodeCloneArgsSetTid(ctx *Context, data []byte, size uint64) []string {
	var parts []string
	setTidPtr := h.u64OrZero(data, 64)
	setTidSize := h.u64OrZero(data, 72)

	if setTidPtr != 0 && setTidSize > 0 {
		if setTidSize <= clone3SetTidMaxEntries {
			setTidBytes := uint32(setTidSize * 4)
			if setTidData, ok := bpfNestedBytesPayload(
				ctx, clone3SetTidPayloadArgIndex, setTidPtr, setTidBytes); ok {
				if setTidText, ok := formatClone3SetTidPayload(setTidData, setTidSize); ok {
					parts = append(parts, fmt.Sprintf("set_tid=%s, set_tid_size=%d", setTidText, setTidSize))
					return parts
				}
			}
		}
		parts = append(parts, fmt.Sprintf("set_tid=%#x, set_tid_size=%d", setTidPtr, setTidSize))
	} else if setTidPtr != 0 || setTidSize != 0 {
		parts = append(parts, formatPtr("set_tid", setTidPtr))
		parts = append(parts, fmt.Sprintf("set_tid_size=%d", setTidSize))
	}
	return parts
}

func formatClone3SetTidPayload(data []byte, count uint64) (string, bool) {
	wantLen := int(count) * 4
	if count == 0 || count > clone3SetTidMaxEntries || len(data) < wantLen {
		return "", false
	}

	values := make([]string, 0, int(count))
	for offset := 0; offset < wantLen; offset += 4 {
		value := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		values = append(values, fmt.Sprintf("%d", value))
	}
	return "[" + strings.Join(values, ", ") + "]", true
}

func (h *ProcessHandler) decodeCloneArgsPost(ctx *Context, data []byte, size uint64) string {
	if ctx.Ret <= 0 {
		return ""
	}
	flags := h.u64OrZero(data, 0)
	if size >= 32 && flags&clone3FlagParentSetTID != 0 {
		ptidPtr := h.u64OrZero(data, 24)
		if ptidPtr != 0 {
			return ""
		} else {
			return "{parent_tid=NULL}"
		}
	}
	return ""
}
