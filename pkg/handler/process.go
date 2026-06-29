package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func init() {
	Register("clone3", &ProcessHandler{})
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
	data, ok := ctx.EnterArgSnapshotPrefix(0, BpfEnterArgOffset, capLen)
	if !ok || len(data) == 0 {
		return fmt.Sprintf("%#x", uargs)
	}

	parts := h.decodeCloneArgsCore(data, size)

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

	structStr := "{" + strings.Join(parts, ", ") + "}"
	postStr := h.decodeCloneArgsPost(ctx, data, size)
	if postStr != "" {
		structStr += " => " + postStr
	}
	return structStr
}

func (h *ProcessHandler) u64OrZero(data []byte, off int) uint64 {
	if len(data) >= off+8 {
		return binary.LittleEndian.Uint64(data[off : off+8])
	}
	return 0
}

func (h *ProcessHandler) decodeCloneArgsCore(data []byte, size uint64) []string {
	var parts []string
	flags := h.u64OrZero(data, 0)
	if size >= 8 {
		parts = append(parts, "flags="+meta.DecodeFlags(flags, "clone3_flags"))
	}
	if size >= 16 {
		pfd := h.u64OrZero(data, 8)
		if pfd != 0 || (flags&0x00001000 != 0) { // CLONE_PIDFD
			parts = append(parts, formatPtr("pidfd", pfd))
		}
	}
	if size >= 24 {
		ctid := h.u64OrZero(data, 16)
		if ctid != 0 || (flags&0x01000000 != 0) { // CLONE_CHILD_SETTID
			parts = append(parts, formatPtr("child_tid", ctid))
		}
	}
	if size >= 32 {
		ptid := h.u64OrZero(data, 24)
		if ptid != 0 || (flags&0x00100000 != 0) { // CLONE_PARENT_SETTID
			parts = append(parts, formatPtr("parent_tid", ptid))
		}
	}
	if size >= 40 {
		sig := h.u64OrZero(data, 32)
		if sig == 0 {
			parts = append(parts, "exit_signal=0")
		} else {
			parts = append(parts, fmt.Sprintf("exit_signal=%s", meta.DecodeFlags(sig, "signalnames")))
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
		if tls != 0 || (flags&0x00080000 != 0) { // CLONE_SETTLS
			parts = append(parts, formatPtr("tls", tls))
		}
	}
	return parts
}

func (h *ProcessHandler) decodeCloneArgsSetTid(ctx *Context, data []byte, size uint64) []string {
	var parts []string
	setTidPtr := h.u64OrZero(data, 64)
	setTidSize := h.u64OrZero(data, 72)

	if setTidPtr != 0 && setTidSize > 0 {
		parts = append(parts, fmt.Sprintf("set_tid=%#x, set_tid_size=%d", setTidPtr, setTidSize))
	} else if setTidPtr != 0 || setTidSize != 0 {
		parts = append(parts, formatPtr("set_tid", setTidPtr))
		parts = append(parts, fmt.Sprintf("set_tid_size=%d", setTidSize))
	}
	return parts
}

func (h *ProcessHandler) decodeCloneArgsPost(ctx *Context, data []byte, size uint64) string {
	if ctx.Ret <= 0 {
		return ""
	}
	flags := h.u64OrZero(data, 0)
	if size >= 32 && (flags&0x00100000 != 0) { // CLONE_PARENT_SETTID
		ptidPtr := h.u64OrZero(data, 24)
		if ptidPtr != 0 {
			return ""
		} else {
			return "{parent_tid=NULL}"
		}
	}
	return ""
}
