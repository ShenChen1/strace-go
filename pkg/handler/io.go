package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func init() {
	h := &IoHandler{}
	Register("readv", h)
	Register("writev", h)
	Register("preadv", h)
	Register("pwritev", h)
	Register("preadv2", h)
	Register("pwritev2", h)
	Register("process_vm_readv", h)
	Register("process_vm_writev", h)
	Register("vmsplice", h)
}

type IoHandler struct {
	DefaultHandler
}

func (h *IoHandler) Handle(ctx *Context) Result {
	res := Result{}
	
	// Fallback to DefaultHandler for scalars, we only override iovec arrays
	argCount := h.getArgCount(ctx)
	for i := 0; i < argCount; i++ {
		argTyp := ctx.ScMeta.ArgTypes[i]
		argName := ctx.ScMeta.Args[i]
		val := ctx.Args[i]
		
		if strings.Contains(argTyp, "struct iovec *") {
			// Find the corresponding count argument
			// For readv/writev/preadv/pwritev/preadv2/pwritev2, count is the next argument (iovcnt)
			// For process_vm_readv/process_vm_writev, count is the next argument (liovcnt/riovcnt)
			// For vmsplice, count is the next argument (nr_segs)
			countVal := uint64(0)
			if i+1 < argCount {
				countVal = ctx.Args[i+1]
			}
			
			isWrite := strings.Contains(ctx.SysName, "writev") || ctx.SysName == "vmsplice"
			
			// For process_vm_writev, local_iov is read, remote_iov is write(remote memory not readable by us typically unless we read remote process, but we use Tid so we read current process)
			// Actually process_vm_writev writes TO remote process FROM local_iov. So local_iov is isWrite=true.
			// remote_iov is just pointers in remote process, we can't easily dereference without knowing remote pid.
			// Let's just treat remote_iov as no-data read for now.
			if argName == "remote_iov" {
				isWrite = false
			}
			
			res.ArgParts = append(res.ArgParts, h.decodeIovecArray(ctx, val, countVal, isWrite, ctx.Ret))
			continue
		}
		
		// If not iovec, use default logic
		if part, ok := h.decodeXlat(ctx, argName, val); ok {
			res.ArgParts = append(res.ArgParts, part)
			continue
		}
		
		if strings.Contains(argTyp, "*") {
			if val == 0 {
				res.ArgParts = append(res.ArgParts, "NULL")
				continue
			}
			if part, ok := h.decodeStruct(ctx, i, argTyp, val); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}
			if part, ok := h.decodePointer(ctx, i, argTyp, argName, val, &res); ok {
				res.ArgParts = append(res.ArgParts, part)
				continue
			}
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", val))
			continue
		}
		
		res.ArgParts = append(res.ArgParts, h.decodeScalar(ctx, argTyp, argName, val))
	}
	
	return res
}

func (h *IoHandler) decodeIovecArray(ctx *Context, addr uint64, count uint64, isWrite bool, ret int64) string {
	if addr == 0 { return "NULL" }
	if count == 0 { return "[]" }
	
	limit := 16
	readCount := int(count)
	if readCount > limit { readCount = limit }
	
	data, _ := ctx.MemReader.ReadRobust(ctx.Tid, addr, readCount*16, true)
	if len(data) == 0 { return fmt.Sprintf("%#x", addr) }
	
	actualCount := len(data) / 16
	var parts []string
	
	bytesRemaining := ret
	if isWrite {
		bytesRemaining = -1 // No limit based on return value for writes
	}
	
	for i := 0; i < actualCount; i++ {
		base := binary.LittleEndian.Uint64(data[i*16 : i*16+8])
		length := binary.LittleEndian.Uint64(data[i*16+8 : i*16+16])
		
		shouldReadData := isWrite || (!isWrite && ret > 0 && ctx.ProbeRetExit >= 0)
		
		if shouldReadData {
			printLen := int(length)
			if !isWrite && bytesRemaining >= 0 {
				if int64(printLen) > bytesRemaining {
					printLen = int(bytesRemaining)
				}
				bytesRemaining -= int64(printLen)
			}
			
			strLimit := ctx.Opts.StringLimit
			if strLimit <= 0 { strLimit = 32 }
			if printLen > strLimit { printLen = strLimit }
			
			buf, _ := ctx.MemReader.ReadRobust(ctx.Tid, base, printLen, true)
			if len(buf) > 0 {
				parts = append(parts, fmt.Sprintf("{iov_base=%s, iov_len=%d}", format.BufferEscape(buf, strLimit, int(length), 0), length))
			} else {
				parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
			}
		} else {
			parts = append(parts, fmt.Sprintf("{iov_base=%#x, iov_len=%d}", base, length))
		}
	}
	
	res := "[" + strings.Join(parts, ", ") + "]"
	if len(data) < readCount*16 || int(count) > limit {
		res = strings.TrimSuffix(res, "]") + ", ...]"
	}
	return res
}
