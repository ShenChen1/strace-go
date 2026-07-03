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
		if part, ok := h.formatSockoptValAndLen(ctx, i, argName, val); ok {
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
	inLen, readInSuccess := h.getSockaddrLenSnapshot(ctx, false)

	if ctx.Ret >= 0 {
		outLen, readOutSuccess := h.getSockaddrLenSnapshot(ctx, true)
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
	data, readSuccess := h.networkBufferSnapshot(ctx, sz)

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
	if sz == 0 {
		return format.Buffer(nil, ctx.Opts.StringLimit, 0)
	}

	data, readSuccess := h.networkBufferSnapshot(ctx, sz)
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

	if isOutSyscall {
		inLen, _ = h.getSockaddrLenSnapshot(ctx, false)
	}

	effectiveLen := alen
	if isOutSyscall && inLen > 0 && inLen < alen {
		effectiveLen = inLen
	}

	readSize := 128
	if effectiveLen > 0 {
		readSize = int(effectiveLen)
		if readSize < 2 {
			readSize = 2
		}
		if readSize > 128 {
			readSize = 128
		}
	}

	sdata, readSuccess := h.sockaddrSnapshot(ctx, readSize)
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
		if outLen, ok := h.getSockaddrLenSnapshot(ctx, true); ok {
			return outLen
		}
		return 0
	}
	if ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" {
		if ctx.Args[2] == 0 {
			return 0
		}
		if outLen, ok := h.getSockaddrLenSnapshot(ctx, true); ok {
			return outLen
		}
	}
	return alen
}

func (h *NetworkHandler) getSockaddrLenSnapshot(ctx *Context, isExit bool) (uint32, bool) {
	argIndex := 2
	if ctx.ScMeta.Name == "recvfrom" {
		argIndex = 5
	}
	direction := PayloadDirectionIn
	if isExit {
		direction = PayloadDirectionOut
	}
	if data, ok := ctx.PayloadBytes(argIndex, direction); ok && len(data) >= 4 {
		return binary.LittleEndian.Uint32(data), true
	}
	return 0, false
}

func (h *NetworkHandler) networkBufferSnapshot(ctx *Context, size int) ([]byte, bool) {
	if ctx.ScMeta.Name == "recvfrom" {
		if data, ok := ctx.PayloadBytes(1, PayloadDirectionOut); ok {
			return boundedBpfStructData(data, size)
		}
		return nil, false
	}
	if data, ok := ctx.PayloadBytes(1, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func (h *NetworkHandler) sockaddrSnapshot(ctx *Context, size int) ([]byte, bool) {
	switch ctx.ScMeta.Name {
	case "bind", "connect":
		if data, ok := ctx.PayloadStruct(1, PayloadDirectionIn); ok {
			return boundedBpfStructData(data, size)
		}
	case "sendto":
		if data, ok := ctx.PayloadStruct(4, PayloadDirectionIn); ok {
			return boundedBpfStructData(data, size)
		}
	case "recvfrom", "accept", "accept4", "getsockname", "getpeername":
		argIndex := 1
		if ctx.ScMeta.Name == "recvfrom" {
			argIndex = 4
		}
		if data, ok := ctx.PayloadStruct(argIndex, PayloadDirectionOut); ok {
			return boundedBpfStructData(data, size)
		}
	}
	return nil, false
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

func (h *NetworkHandler) formatSockoptValAndLen(ctx *Context, i int, argName string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "getsockopt" && i == 4 { // optlen (socklen_t *)
		if val == 0 {
			return "NULL", true
		}
		if ctx.Ret < 0 && ctx.Ret >= -4095 && ctx.ProbeRetExit < 0 {
			return fmt.Sprintf("%#x", val), true
		}
		if data, ok := ctx.PayloadBytes(4, PayloadDirectionOut); ok && len(data) >= 4 {
			return fmt.Sprintf("[%d]", binary.LittleEndian.Uint32(data)), true
		}
		return fmt.Sprintf("%#x", val), true
	}
	if ctx.ScMeta.Name == "setsockopt" && i == 4 { // optlen (socklen_t)
		return fmt.Sprintf("%d", val), true
	}
	// For optval (i == 3)
	if (ctx.ScMeta.Name == "getsockopt" || ctx.ScMeta.Name == "setsockopt") && i == 3 {
		if val == 0 {
			return "NULL", true
		}
		return fmt.Sprintf("%#x", val), true
	}
	return "", false
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
