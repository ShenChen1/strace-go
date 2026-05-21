package handler

import (
	"encoding/binary"
	"fmt"

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

func (h *NetworkHandler) Handle(ctx *Context) Result {
	var res Result

	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]

		if argName == "fd" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
			continue
		}

		if (argName == "upeer_addrlen" || argName == "usockaddr_len" || argName == "addr_len") &&
			(ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			inLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[768:772])
			if inLen == 0 || ctx.ProbeRetEnter < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 4, false); err == nil && len(d) == 4 {
					inLen = binary.LittleEndian.Uint32(d)
				}
			}
			outLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
			if outLen == 0 || ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 4, true); err == nil && len(d) == 4 {
					outLen = binary.LittleEndian.Uint32(d)
				}
			}

			if ctx.Ret >= 0 {
				if inLen != outLen && inLen != 0 {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d => %d]", inLen, outLen))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", outLen))
				}
			} else {
				if inLen != 0 {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", inLen))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				}
			}
			continue
		}

		if argTyp == "struct sockaddr *" || argName == "addr" || argName == "usockaddr" {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			aidx := 2
			if ctx.ScMeta.Name == "sendto" { aidx = 5 } else if ctx.ScMeta.Name == "recvfrom" { aidx = 5 }
			if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" { aidx = 2 }

			outLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
			inLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[768:772])
			
			// For bind/connect/sendto, alen is arg 2 or 5
			if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" || ctx.ScMeta.Name == "sendto" {
				alen := uint32(ctx.Args[aidx])
				inLen = alen
				outLen = alen
			}

			if (outLen == 0 && inLen == 0) || ctx.ProbeRetExit < 0 {
				// Try to read addrlen from memory if it's a pointer
				if ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom" {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[aidx], 4, true); err == nil && len(d) == 4 {
						outLen = binary.LittleEndian.Uint32(d)
					}
				}
			}

			capLen := outLen
			if inLen > 0 && inLen < outLen {
				capLen = inLen
			}
			if capLen == 0 { capLen = inLen }
			if capLen > 256 { capLen = 256 }
			if capLen == 0 { capLen = 16 }

			offset := uint32(0)
			if ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom" {
				offset = 1024
			}

			sdata := ctx.StrArgBuf[offset : offset+capLen]
			fam := uint16(0)
			if len(sdata) >= 2 { fam = binary.LittleEndian.Uint16(sdata) }

			readSuccess := ctx.ProbeRetExit >= 0
			if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" || ctx.ScMeta.Name == "sendto" {
				readSuccess = ctx.ProbeRetEnter >= 0
			}

			if ctx.Ret >= 0 && (!readSuccess || (fam == 0 && capLen > 0)) {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(capLen), true); err == nil && len(d) == int(capLen) {
					sdata = d
					readSuccess = true
				}
			}

			if ctx.Ret < 0 || !readSuccess {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				continue
			}

			validLen := outLen
			if inLen > 0 && inLen < validLen {
				validLen = inLen
			}
			if len(sdata) > int(validLen) {
				sdata = sdata[:validLen]
			}

			res.ArgParts = append(res.ArgParts, format.Sockaddr(sdata, outLen, inLen))
			continue
		}

		if (ctx.ScMeta.Name == "setsockopt" || ctx.ScMeta.Name == "getsockopt") && argName == "optname" {
			level := ctx.Args[1]
			xlat := "sock_options"
			if level == 1 { // SOL_SOCKET
				xlat = "sock_options"
			} else if level == 0 { // IPPROTO_IP
				xlat = "sock_ip_options"
			} else if level == 6 { // IPPROTO_TCP
				xlat = "sock_tcp_options"
			}
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlat))
			continue
		}

		if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
			continue
		}

		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
	}
	return res
}
