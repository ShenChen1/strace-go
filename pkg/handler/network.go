package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &NetworkHandler{}
	Register("accept", h)
	Register("accept4", h)
	Register("getsockname", h)
	Register("getpeername", h)
	Register("recvfrom", h)
	Register("sendto", h)
	Register("connect", h)
	Register("bind", h)
	Register("socket", h)
	Register("setsockopt", h)
	Register("getsockopt", h)
}

// NetworkHandler handles sockaddr and socket-related syscalls.
type NetworkHandler struct {
	DefaultHandler
}

// Handle handles sockaddr and socket-related syscalls.
// IMPACT: Refactored Handle to delegate logic to helpers, ensuring functions are under 80 LOC.
func (h *NetworkHandler) Handle(ctx *Context) Result {
	var res Result
	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]

		if part, ok := h.formatNetworkFd(argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		if part, ok := h.formatNetworkLengthArg(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		if part, ok := h.formatNetworkAddrLen(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		if part, ok := h.formatNetworkBuffer(ctx, i, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		if part, ok := h.formatSockaddr(ctx, i, argName, argTyp, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		if part, ok := h.formatSockopt(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}

		res.ArgParts = append(res.ArgParts, h.formatFallback(ctx, i, argName, argTyp, val))
	}
	return res
}

func (h *NetworkHandler) formatNetworkFd(argName string, val uint64) (string, bool) {
	if argName == "fd" {
		return fmt.Sprintf("%d", int32(val)), true
	}
	return "", false
}

func (h *NetworkHandler) formatNetworkLengthArg(ctx *Context, argName string, val uint64) (string, bool) {
	if (argName == "len" || argName == "size" || argName == "count") && ctx.ScMeta.Name != "socket" {
		return fmt.Sprintf("%d", val), true
	}
	return "", false
}

func (h *NetworkHandler) formatNetworkAddrLen(ctx *Context, argName string, val uint64) (string, bool) {
	if !(argName == "upeer_addrlen" || argName == "usockaddr_len" || argName == "addr_len") {
		return "", false
	}
	isAcceptFamily := ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom"
	if !isAcceptFamily {
		return "", false
	}

	if val == 0 {
		return "NULL", true
	}
	readInSuccess := ctx.ProbeRetEnter >= 0
	inLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[768:772])
	if !readInSuccess || inLen == 0 {
		if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 4, false); err == nil && len(d) == 4 {
			inLen = binary.LittleEndian.Uint32(d)
			readInSuccess = true
		}
	}

	if ctx.Ret >= 0 {
		readOutSuccess := ctx.ProbeRetExit >= 0
		outLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
		if !readOutSuccess || outLen == 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, 4, true); err == nil && len(d) == 4 {
				outLen = binary.LittleEndian.Uint32(d)
				readOutSuccess = true
			}
		}
		if !readOutSuccess {
			return fmt.Sprintf("%#x", val), true
		}
		if readInSuccess && inLen != outLen && inLen != 0 {
			return fmt.Sprintf("[%d => %d]", inLen, outLen), true
		}
		return fmt.Sprintf("[%d]", outLen), true
	}

	if !readInSuccess {
		return fmt.Sprintf("%#x", val), true
	}
	return fmt.Sprintf("[%d]", inLen), true
}

func (h *NetworkHandler) formatNetworkBuffer(ctx *Context, i int, val uint64) (string, bool) {
	if !(ctx.ScMeta.Name == "sendto" || ctx.ScMeta.Name == "recvfrom") || i != 1 {
		return "", false
	}
	if val == 0 {
		return "NULL", true
	}

	fdInfo := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, int32(ctx.Args[0]))]
	if strings.Contains(fdInfo, "AF_NETLINK") {
		return h.formatNetlinkBuf(ctx, val), true
	}
	return h.formatStandardBuf(ctx, val), true
}

func (h *NetworkHandler) formatNetlinkBuf(ctx *Context, val uint64) string {
	sz := int(ctx.Args[2])
	if sz > 512 {
		sz = 512
	}
	data := ctx.StrArgBuf[0:sz]
	readSuccess := ctx.ProbeRetEnter >= 0
	if ctx.ScMeta.Name == "recvfrom" {
		data = ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+sz]
		readSuccess = ctx.ProbeRetExit >= 0
	}

	if !readSuccess {
		if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, sz, ctx.ScMeta.Name == "recvfrom"); err == nil && len(d) >= sz {
			data = d
			readSuccess = true
		}
	}

	if readSuccess && len(data) >= 16 {
		return format.Netlink(data)
	}
	return fmt.Sprintf("%#x", val)
}

func (h *NetworkHandler) formatStandardBuf(ctx *Context, val uint64) string {
	sz := int(ctx.Args[2])
	if ctx.ScMeta.Name == "recvfrom" {
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", val)
		}
		sz = int(ctx.Ret)
	}
	if sz > 512 {
		sz = 512
	}
	if sz < 0 {
		sz = 0
	}

	data := ctx.StrArgBuf[0:sz]
	readSuccess := ctx.ProbeRetEnter >= 0
	if ctx.ScMeta.Name == "recvfrom" {
		data = ctx.StrArgBuf[BpfExitArgOffset : BpfExitArgOffset+sz]
		readSuccess = ctx.ProbeRetExit >= 0
	}

	if !readSuccess {
		if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, sz, ctx.ScMeta.Name == "recvfrom"); err == nil && len(d) >= sz {
			data = d
			readSuccess = true
		}
	}
	if readSuccess {
		actualLen := int(ctx.Args[2])
		if ctx.ScMeta.Name == "recvfrom" {
			actualLen = int(ctx.Ret)
		}
		return format.Buffer(data, ctx.Opts.StringLimit, actualLen)
	}
	return fmt.Sprintf("%#x", val)
}

func (h *NetworkHandler) formatSockaddr(ctx *Context, i int, argName, argTyp string, val uint64) (string, bool) {
	if !(argTyp == "struct sockaddr *" || argName == "addr" || argName == "usockaddr" || argName == "addr_user") {
		return "", false
	}
	if (ctx.ScMeta.Name == "sendto" || ctx.ScMeta.Name == "recvfrom") && i == 1 {
		return "", false
	}
	if val == 0 {
		return "NULL", true
	}

	isOutSyscall := ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom"
	if isOutSyscall && ctx.Ret < 0 {
		return fmt.Sprintf("%#x", val), true
	}

	alen := h.getSockaddrLen(ctx)
	inLen := uint32(0)
	offset := uint32(0)

	if isOutSyscall {
		offset = 1024
		if ctx.ScMeta.Name == "recvfrom" {
			offset = 1536
		}
		inLen = binary.LittleEndian.Uint32(ctx.StrArgBuf[768:772])
	}

	effectiveLen := alen
	if isOutSyscall && inLen > 0 && inLen < alen {
		effectiveLen = inLen
	}

	readSize := 128
	if effectiveLen > 0 {
		readSize = int(effectiveLen)
		if readSize < 2 { readSize = 2 }
		if readSize > 128 { readSize = 128 }
	}

	sdata := ctx.StrArgBuf[offset : offset+uint32(readSize)]
	readSuccess := ctx.ProbeRetExit >= 0
	if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" || ctx.ScMeta.Name == "sendto" {
		readSuccess = ctx.ProbeRetEnter >= 0
	}

	if !readSuccess {
		if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, readSize, ctx.ScMeta.Name == "recvfrom"); err == nil && len(d) >= 2 {
			sdata = d
			readSuccess = true
		}
	}

	if !readSuccess {
		return fmt.Sprintf("%#x", val), true
	}
	return format.Sockaddr(sdata, alen, alen), true
}

func (h *NetworkHandler) getSockaddrLen(ctx *Context) uint32 {
	alen := uint32(0)
	if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" {
		return uint32(ctx.Args[2])
	}
	if ctx.ScMeta.Name == "sendto" {
		return uint32(ctx.Args[5])
	}
	if ctx.ScMeta.Name == "recvfrom" {
		alen = binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
		if alen == 0 || ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Tid, ctx.Args[5], 4, true); err == nil && len(d) == 4 {
				alen = binary.LittleEndian.Uint32(d)
			}
		}
		return alen
	}
	if ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" {
		addrlenPtr := ctx.Args[2]
		if addrlenPtr != 0 {
			alen = binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
			if alen == 0 || ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Tid, addrlenPtr, 4, true); err == nil && len(d) == 4 {
					alen = binary.LittleEndian.Uint32(d)
				}
			}
		}
	}
	return alen
}

func (h *NetworkHandler) formatSockopt(ctx *Context, argName string, val uint64) (string, bool) {
	if !(ctx.ScMeta.Name == "setsockopt" || ctx.ScMeta.Name == "getsockopt") || argName != "optname" {
		return "", false
	}
	level := ctx.Args[1]
	xlat := "sock_options"
	if level == 1 { // SOL_SOCKET
		xlat = "sock_options"
	} else if level == 0 { // IPPROTO_IP
		xlat = "sock_ip_options"
	} else if level == 6 { // IPPROTO_TCP
		xlat = "sock_tcp_options"
	}
	return meta.DecodeFlags(val, xlat), true
}

func (h *NetworkHandler) formatFallback(ctx *Context, i int, argName, argTyp string, val uint64) string {
	if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
		return meta.DecodeFlags(val, xlatName)
	}

	if val == 0 && (strings.Contains(argTyp, "*") || (strings.Contains(argName, "addr") && !strings.Contains(argName, "len"))) {
		if (ctx.ScMeta.Name == "sendto" || ctx.ScMeta.Name == "recvfrom") && i == 5 {
			return "0"
		}
		return "NULL"
	}

	if strings.Contains(argName, "len") || strings.Contains(argName, "size") || strings.Contains(argName, "count") {
		return fmt.Sprintf("%d", val)
	}
	return fmt.Sprintf("%#x", val)
}
