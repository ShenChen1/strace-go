package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func init() {
	h := &SelectHandler{}
	Register("select", h)
	Register("_newselect", h)
	Register("pselect6", h)
	
	ph := &PollHandler{}
	Register("poll", ph)
	Register("ppoll", ph)
}

type SelectHandler struct{}

// ... (SelectHandler implementation)

type PollHandler struct{}

func (h *PollHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfds := int(ctx.Args[1])
	
	ptr := ctx.Args[0]
	if ptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		capLen := nfds * 8
		if capLen > 512 { capLen = 512 }
		data := ctx.StrArgBuf[0:capLen]
		readSuccess := ctx.ProbeRetEnter >= 0
		if !readSuccess {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, capLen, false); err == nil {
				data = d
				readSuccess = true
			}
		}
		
		if readSuccess {
			res.ArgParts = append(res.ArgParts, formatPollfds(data, nfds, false, ctx))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}
	
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfds))
	
	if ctx.SysName == "poll" {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[2])))
	} else {
		// ppoll timeout (timespec)
		tptr := ctx.Args[2]
		if tptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			data := ctx.StrArgBuf[512 : 512+16]
			if ctx.ProbeRetEnter < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, tptr, 16, false); err == nil { data = d }
			}
			res.ArgParts = append(res.ArgParts, format.Timespec(data))
		}
		res.ArgParts = append(res.ArgParts, "NULL") // sigmask
		res.ArgParts = append(res.ArgParts, "8")    // sigsetsize
	}
	
	if ctx.Ret == 0 { 
		res.ReturnDesc = "Timeout" 
	} else if ctx.Ret > 0 {
		// Format revents in return desc
		capLen := nfds * 8
		if capLen > 512 { capLen = 512 }
		data := ctx.StrArgBuf[1024 : 1024+capLen]
		if ctx.ProbeRetExit < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, capLen, true); err == nil { data = d }
		}
		
		parts := []string{}
		for i := 0; i < nfds && len(parts) < int(ctx.Ret); i++ {
			off := i * 8
			if len(data) < off+8 { break }
			fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
			revents := binary.LittleEndian.Uint16(data[off+6 : off+8])
			if revents != 0 {
				parts = append(parts, fmt.Sprintf("{fd=%d, revents=%s}", fd, meta.DecodeFlags(uint64(revents), "pollflags")))
			}
		}
		if len(parts) > 0 {
			res.ReturnDesc = "[" + strings.Join(parts, ", ") + "]"
		}
	}
	
	return res
}

func formatPollfds(data []byte, nfds int, hasOutput bool, ctx *Context) string {
	parts := []string{}
	limit := 16
	for i := 0; i < nfds && i < limit; i++ {
		off := i * 8
		if len(data) < off+8 { break }
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := binary.LittleEndian.Uint16(data[off+4 : off+6])
		
		if fd < 0 {
			parts = append(parts, fmt.Sprintf("{fd=%d}", fd))
		} else {
			s := fmt.Sprintf("{fd=%d, events=%s", fd, meta.DecodeFlags(uint64(events), "pollflags"))
			if hasOutput {
				revents := binary.LittleEndian.Uint16(data[off+6 : off+8])
				if revents != 0 {
					s += fmt.Sprintf(", revents=%s", meta.DecodeFlags(uint64(revents), "pollflags"))
				}
			}
			s += "}"
			parts = append(parts, s)
		}
	}
	if nfds > limit { parts = append(parts, "...") }
	return "[" + strings.Join(parts, ", ") + "]"
}


func (h *SelectHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfds := int(int32(ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfds))

	// Handle fd_sets
	for i := 1; i <= 3; i++ {
		ptr := ctx.Args[i]
		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			continue
		}
		
		// enter capture
		off := (i - 1) * 128
		data := ctx.StrArgBuf[off : off+128]
		if ctx.ProbeRetEnter < 0 {
			// Read from memory
			sz := (nfds + 7) / 8
			if sz > 128 { sz = 128 }
			if sz > 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, sz, false); err == nil {
					data = d
				}
			}
		}
		res.ArgParts = append(res.ArgParts, format.FdSet(data, nfds))
	}

	// Handle timeout
	tptr := ctx.Args[4]
	if tptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		// timeout on entry
		data := ctx.StrArgBuf[384 : 384+16]
		if ctx.ProbeRetEnter < 0 {
			if d, err := ctx.MemReader.ReadRobust(ctx.Pid, tptr, 16, false); err == nil { data = d }
		}
		res.ArgParts = append(res.ArgParts, format.Timeval(data))
	}

	// Post-syscall return value and output sets
	if ctx.Ret == 0 {
		res.ReturnDesc = "Timeout"
	}

	if ctx.Ret > 0 {
		outParts := []string{}
		for i := 1; i <= 3; i++ {
			ptr := ctx.Args[i]
			if ptr == 0 { continue }
			
			off := 1024 + (i-1)*128
			data := ctx.StrArgBuf[off : off+128]
			if ctx.ProbeRetExit < 0 {
				sz := (nfds + 7) / 8
				if sz > 128 { sz = 128 }
				if sz > 0 {
					if d, err := ctx.MemReader.ReadRobust(ctx.Pid, ptr, sz, true); err == nil {
						data = d
					}
				}
			}
			// Check if any bit is set in output set
			hasAny := false
			for _, b := range data { if b != 0 { hasAny = true; break } }
			if hasAny {
				label := "out"
				if i == 2 { label = "write" } else if i == 3 { label = "except" }
				outParts = append(outParts, label+" "+format.FdSet(data, nfds))
			}
		}
		
		// timeout on exit (left)
		if tptr != 0 {
			data := ctx.StrArgBuf[1408 : 1408+16]
			if ctx.ProbeRetExit < 0 {
				if d, err := ctx.MemReader.ReadRobust(ctx.Pid, tptr, 16, true); err == nil { data = d }
			}
			outParts = append(outParts, "left "+format.Timeval(data))
		}
		if len(outParts) > 0 {
			res.ReturnDesc = strings.Join(outParts, ", ")
		}
	}

	return res
}
