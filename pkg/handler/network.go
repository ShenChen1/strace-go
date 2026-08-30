package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func registerBuiltinNetwork(r *Registry) {
	h := &NetworkHandler{}
	r.Register("accept", h)
	r.Register("accept4", h)
	r.Register("getsockname", h)
	r.Register("getpeername", h)
	r.Register("recvfrom", h)
	r.Register("sendto", h)
	r.Register("connect", h)
	r.Register("bind", h)
	r.Register("socket", h)
	r.Register("setsockopt", h)
	r.Register("getsockopt", h)
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

		if part, ok := h.formatNetworkFd(ctx, argName, val); ok {
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
		if part, ok := h.formatSocketArgument(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}

		res.ArgParts = append(res.ArgParts, h.formatFallback(ctx, i, argName, argTyp, val))
	}
	return res
}

func (h *NetworkHandler) formatNetworkFd(ctx *Context, argName string, val uint64) (string, bool) {
	if argName == "fd" {
		return FormatFdWithPath(ctx, int32(val)), true
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

	fdInfo := ""
	if ctx.FDStateView != nil {
		fdInfo, _ = ctx.FDStateView.Path(ctx.TargetPid, int32(ctx.Args[0]))
	}
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
		return format.NetlinkWithCatalog(catalogForContext(ctx), data)
	}
	return fmt.Sprintf("%#x", val)
}

func (h *NetworkHandler) formatStandardBuf(ctx *Context, val uint64) string {
	sz := int(ctx.Args[2])
	if ctx.ScMeta.Name == "recvfrom" {
		if ctx.Ret < 0 {
			return fmt.Sprintf("%#x", val)
		}
		sz = recvfromBufferDisplayLen(ctx)
	}
	if sz > 512 {
		sz = 512
	}
	if sz < 0 {
		sz = 0
	}
	if sz == 0 {
		return format.Buffer(nil, ctx.Opts.StringLimitValue(), 0)
	}

	data, readSuccess := h.networkBufferSnapshot(ctx, sz)
	if readSuccess {
		actualLen := int(ctx.Args[2])
		if ctx.ScMeta.Name == "recvfrom" {
			actualLen = recvfromBufferDisplayLen(ctx)
		}
		return format.Buffer(data, ctx.Opts.StringLimitValue(), actualLen)
	}
	return fmt.Sprintf("%#x", val)
}

func recvfromBufferDisplayLen(ctx *Context) int {
	count := int(ctx.Args[2])
	if count < 0 {
		count = 0
	}
	ret := int(ctx.Ret)
	if ret < count {
		return ret
	}
	return count
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
	} else if level == 270 { // SOL_NETLINK
		xlat = "sock_netlink_options"
	}
	return decodeFlags(ctx, val, xlat), true
}

func (h *NetworkHandler) formatSockoptValAndLen(ctx *Context, i int, argName string, val uint64) (string, bool) {
	if ctx.ScMeta.Name == "getsockopt" && i == 4 { // optlen (socklen_t *)
		if val == 0 {
			return "NULL", true
		}
		inLen, inOK := h.sockoptLengthSnapshot(ctx, PayloadDirectionIn)
		if outLen, ok := h.sockoptLengthSnapshot(ctx, PayloadDirectionOut); ok {
			if inOK && inLen != outLen {
				return fmt.Sprintf("[%d => %d]", inLen, outLen), true
			}
			return fmt.Sprintf("[%d]", outLen), true
		}
		if inOK {
			return fmt.Sprintf("[%d]", inLen), true
		}
		return fmt.Sprintf("%#x", val), true
	}
	if ctx.ScMeta.Name == "setsockopt" && i == 4 { // optlen (socklen_t)
		return fmt.Sprintf("%d", int32(uint32(val))), true
	}
	// For optval (i == 3)
	if (ctx.ScMeta.Name == "getsockopt" || ctx.ScMeta.Name == "setsockopt") && i == 3 {
		if val == 0 {
			return "NULL", true
		}
		direction := PayloadDirectionIn
		if ctx.ScMeta.Name == "getsockopt" {
			direction = PayloadDirectionOut
		}
		if direction == PayloadDirectionOut && ctx.Ret >= 0 && isNetlinkListMemberships(ctx) {
			if length, ok := h.sockoptLengthSnapshot(ctx, PayloadDirectionIn); ok && length < 4 {
				return "[]", true
			}
		}
		if section, ok := h.sockoptValueSnapshot(ctx, direction); ok {
			if formatted, formattedOK := h.formatSockoptValue(ctx, direction, section); formattedOK {
				return formatted, true
			}
		}
		return fmt.Sprintf("%#x", val), true
	}
	return "", false
}

func (h *NetworkHandler) sockoptLengthSnapshot(ctx *Context, direction PayloadDirection) (uint32, bool) {
	data, ok := ctx.PayloadBytes(4, direction)
	if !ok || len(data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}

func (h *NetworkHandler) sockoptValueSnapshot(ctx *Context, direction PayloadDirection) (PayloadSection, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == 3 && section.Kind == PayloadKindBytes &&
			section.Direction == direction && section.ProbeRet == 0 && len(section.Data) > 0 {
			return section, true
		}
	}
	return PayloadSection{}, false
}

func (h *NetworkHandler) formatSockoptValue(ctx *Context, direction PayloadDirection, section PayloadSection) (string, bool) {
	data := section.Data
	if isNetlinkListMemberships(ctx) && direction == PayloadDirectionOut {
		return formatNetlinkMemberships(data), true
	}
	if len(data) >= 4 && (section.UserLen == 4 || (isFixedIntSockopt(ctx) && section.UserLen >= 4)) {
		value := uint64(uint32(binary.LittleEndian.Uint32(data)))
		if int32(uint32(ctx.Args[2])) == 74 {
			return fmt.Sprintf("[%s]", decodeFlags(ctx, value, "sockopt_txrehash_vals")), true
		}
		return fmt.Sprintf("[%d]", int32(value)), true
	}
	if isFixedIntSockopt(ctx) {
		if direction == PayloadDirectionOut {
			return format.BufferEscape(data, ctx.Opts.StringLimitValue(), len(data), 1), true
		}
		return "", false
	}
	return format.Buffer(data, ctx.Opts.StringLimitValue(), len(data)), true
}

func isNetlinkListMemberships(ctx *Context) bool {
	return int32(uint32(ctx.Args[1])) == 270 && int32(uint32(ctx.Args[2])) == 9
}

func formatNetlinkMemberships(data []byte) string {
	items := make([]string, 0, len(data)/4)
	for offset := 0; offset+4 <= len(data); offset += 4 {
		items = append(items, fmt.Sprintf("%d", binary.LittleEndian.Uint32(data[offset:offset+4])))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func isFixedIntSockopt(ctx *Context) bool {
	level := int32(uint32(ctx.Args[1]))
	option := int32(uint32(ctx.Args[2]))
	if level == 270 {
		return ctx.ScMeta.Name == "setsockopt" || option != 9
	}
	if level != 1 {
		return false
	}
	switch option {
	case 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16,
		18, 19, 27, 29, 30, 32, 33, 34, 35, 36, 37, 40,
		41, 42, 43, 44, 45, 46, 49, 53, 56, 60, 63, 64,
		65, 68, 69, 70, 73, 74, 75, 76, 80, 82, 83, 84:
		return true
	default:
		return false
	}
}

func (h *NetworkHandler) formatFallback(ctx *Context, i int, argName, argTyp string, val uint64) string {
	if xlatName, ok := syscallArgXlat(ctx, ctx.ScMeta.Name, argName); ok {
		return decodeFlags(ctx, val, xlatName)
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
