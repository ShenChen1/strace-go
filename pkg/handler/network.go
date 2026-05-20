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
}

// NetworkHandler handles sockaddr-related syscalls.
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
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 4, false); err == nil {
					inLen = binary.LittleEndian.Uint32(d)
				}
			}
			outLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
			if outLen == 0 || ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, 4, true); err == nil {
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

		if argTyp == "struct sockaddr *" {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			aidx := 2
			if ctx.ScMeta.Name == "sendto" { aidx = 5 } else if ctx.ScMeta.Name == "recvfrom" { aidx = 5 }

			outLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
			if outLen == 0 || ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[aidx], 4, true); err == nil {
					outLen = binary.LittleEndian.Uint32(d)
				}
			}
			inLen := binary.LittleEndian.Uint32(ctx.StrArgBuf[768:772])
			if inLen == 0 || ctx.ProbeRetEnter < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ctx.Args[aidx], 4, false); err == nil {
					inLen = binary.LittleEndian.Uint32(d)
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
			if ctx.Ret >= 0 && (!readSuccess || (fam == 0 && capLen > 0)) {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, val, int(capLen), true); err == nil {
					sdata = d
					readSuccess = true
				}
			}

			if !readSuccess {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				continue
			}

			// The kernel only writes up to inLen bytes, so we shouldn't decode beyond that
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

		if xlatName, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name][argName]; ok {
			res.ArgParts = append(res.ArgParts, meta.DecodeFlags(val, xlatName))
			continue
		}

		// Use default handler for remaining args (like void* buff, size_t len, int flags)
		if argName == "buff" || argName == "ubuf" || argName == "len" || argName == "size" {
			// A trick to reuse default logic for specific argument
			ctxCopy := *ctx
			ctxCopy.ScMeta.Args = []string{argName}
			ctxCopy.ScMeta.ArgTypes = []string{argTyp}
			ctxCopy.Args[0] = val
			defRes := h.DefaultHandler.Handle(&ctxCopy)
			res.ArgParts = append(res.ArgParts, defRes.ArgParts...)
			if defRes.HexDumpStr != "" { res.HexDumpStr = defRes.HexDumpStr }
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
		}
	}
	return res
}
