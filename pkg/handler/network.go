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
// Impact: Decodes sockaddr structures and network buffer parameters. Uses Tid for robust process memory reading.
// IMPACT: Fallback to ReadRobust only when BPF capture fails to avoid user space timing race.
func (h *NetworkHandler) Handle(ctx *Context) Result {
	var res Result

	for i := 0; i < len(ctx.ScMeta.Args); i++ {
		argName, argTyp, val := ctx.ScMeta.Args[i], ctx.ScMeta.ArgTypes[i], ctx.Args[i]

		if argName == "fd" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(val)))
			continue
		}

		if (argName == "len" || argName == "size" || argName == "count") && ctx.ScMeta.Name != "socket" {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", val))
			continue
		}

		if (argName == "upeer_addrlen" || argName == "usockaddr_len" || argName == "addr_len") &&
			(ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
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
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				} else {
					if readInSuccess && inLen != outLen && inLen != 0 {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d => %d]", inLen, outLen))
					} else {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", outLen))
					}
				}
			} else {
				if !readInSuccess {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("[%d]", inLen))
				}
			}
			continue
		}

		if (ctx.ScMeta.Name == "sendto" || ctx.ScMeta.Name == "recvfrom") && i == 1 {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			fdInfo := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, int32(ctx.Args[0]))]
			if strings.Contains(fdInfo, "AF_NETLINK") {
				sz := int(ctx.Args[2])
				if sz > 512 { sz = 512 }
				data := ctx.StrArgBuf[0:sz]
				readSuccess := ctx.ProbeRetEnter >= 0
				if ctx.ScMeta.Name == "recvfrom" { 
					data = ctx.StrArgBuf[1024 : 1024+sz]
					readSuccess = ctx.ProbeRetExit >= 0
				}
				
				if !readSuccess {
					if d, err := ctx.MemReader.ReadRobust(ctx.Tid, val, sz, ctx.ScMeta.Name == "recvfrom"); err == nil && len(d) >= sz {
						data = d
						readSuccess = true
					}
				}
				
				if readSuccess && len(data) >= 16 {
					res.ArgParts = append(res.ArgParts, format.Netlink(data))
					continue
				}
			} else {
				// IMPACT: Decodes network data buffer (buf) into escaped string format for non-netlink sendto/recvfrom.
				sz := int(ctx.Args[2])
				if ctx.ScMeta.Name == "recvfrom" {
					if ctx.Ret < 0 {
						res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
						continue
					}
					sz = int(ctx.Ret)
				}
				if sz > 512 { sz = 512 }
				if sz < 0 { sz = 0 }
				
				data := ctx.StrArgBuf[0:sz]
				readSuccess := ctx.ProbeRetEnter >= 0
				if ctx.ScMeta.Name == "recvfrom" {
					data = ctx.StrArgBuf[1024 : 1024+sz]
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
					res.ArgParts = append(res.ArgParts, format.Buffer(data, ctx.Opts.StringLimit, actualLen))
				} else {
					res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				}
				continue
			}
		}

		if (argTyp == "struct sockaddr *" || argName == "addr" || argName == "usockaddr" || argName == "addr_user") && (ctx.ScMeta.Name != "sendto" && ctx.ScMeta.Name != "recvfrom" || i != 1) {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}

			isOutSyscall := ctx.ScMeta.Name == "accept" || ctx.ScMeta.Name == "accept4" || ctx.ScMeta.Name == "getsockname" || ctx.ScMeta.Name == "getpeername" || ctx.ScMeta.Name == "recvfrom"
			if isOutSyscall && ctx.Ret < 0 {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				continue
			}

			alen := uint32(0)
			if ctx.ScMeta.Name == "bind" || ctx.ScMeta.Name == "connect" { alen = uint32(ctx.Args[2]) }
			if ctx.ScMeta.Name == "sendto" { alen = uint32(ctx.Args[5]) }
			if ctx.ScMeta.Name == "recvfrom" {
				// IMPACT: Prioritize BPF-captured exit addr_len value from StrArgBuf to prevent EFAULT from ptrace fallback.
				alen = binary.LittleEndian.Uint32(ctx.StrArgBuf[772:776])
				if alen == 0 || ctx.ProbeRetExit < 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Tid, ctx.Args[5], 4, true); err == nil && len(d) == 4 {
						alen = binary.LittleEndian.Uint32(d)
					}
				}
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

			offset := uint32(0)
			if isOutSyscall {
				offset = 1024
				// IMPACT: Sets offset to 1536 for recvfrom exit sockaddr to align with dynamic BPF capture rules.
				if ctx.ScMeta.Name == "recvfrom" {
					offset = 1536
				}
			}

			inLen := uint32(0)
			if isOutSyscall {
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
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
				continue
			}

			res.ArgParts = append(res.ArgParts, format.Sockaddr(sdata, alen, alen))
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

		if val == 0 && (strings.Contains(argTyp, "*") || (strings.Contains(argName, "addr") && !strings.Contains(argName, "len"))) {
			if (ctx.ScMeta.Name == "sendto" || ctx.ScMeta.Name == "recvfrom") && i == 5 {
				res.ArgParts = append(res.ArgParts, "0")
			} else {
				res.ArgParts = append(res.ArgParts, "NULL")
			}
		} else {
			if strings.Contains(argName, "len") || strings.Contains(argName, "size") || strings.Contains(argName, "count") {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", val))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			}
		}
	}
	return res
}
