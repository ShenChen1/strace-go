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

const (
	fdSetPayloadSize   = 128
	pollFdSize         = 8
	pollPayloadLimit   = 512
	selectFdSetArgBase = 1
	selectFdSetArgLast = 3
)

func (h *SelectHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfds := int(int32(ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfds))

	h.formatSelectFdSets(ctx, nfds, &res)
	h.formatSelectTimeout(ctx, &res)

	if ctx.Ret == 0 {
		res.ReturnDesc = "Timeout"
	}
	if ctx.Ret > 0 {
		h.formatSelectExit(ctx, nfds, &res)
	}

	return res
}

func (h *SelectHandler) formatSelectFdSets(ctx *Context, nfds int, res *Result) {
	for i := selectFdSetArgBase; i <= selectFdSetArgLast; i++ {
		ptr := ctx.Args[i]
		if ptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
			continue
		}

		if data, ok := selectEnterFdSetPayload(ctx, i, nfds); ok {
			res.ArgParts = append(res.ArgParts, format.FdSet(data, nfds))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}
}

func (h *SelectHandler) formatSelectTimeout(ctx *Context, res *Result) {
	tptr := ctx.Args[4]
	if tptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}

	if data, ok := selectTimeoutPayload(ctx); ok {
		res.ArgParts = append(res.ArgParts, format.Timeval(data))
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", tptr))
	}
}

func (h *SelectHandler) formatSelectExit(ctx *Context, nfds int, res *Result) {
	outParts := []string{}
	setNames := []string{"in", "out", "exc"}
	for i := selectFdSetArgBase; i <= selectFdSetArgLast; i++ {
		ptr := ctx.Args[i]
		if ptr == 0 {
			continue
		}

		if data, ok := selectExitFdSetPayload(ctx, i, nfds); ok {
			hasAny := false
			for j := 0; j < (nfds+7)/8 && j < len(data); j++ {
				if data[j] != 0 {
					hasAny = true
					break
				}
			}
			if hasAny {
				outParts = append(outParts, setNames[i-1]+" "+format.FdSet(data, nfds))
			}
		}
	}

	tptr := ctx.Args[4]
	if tptr != 0 {
		if data, ok := selectExitTimeoutPayload(ctx); ok {
			outParts = append(outParts, "left "+format.Timeval(data))
		}
	}
	if len(outParts) > 0 {
		res.ReturnDesc = strings.Join(outParts, ", ")
	}
}

type PollHandler struct{}

func (h *PollHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfds := int(ctx.Args[1])
	ptr := ctx.Args[0]

	if ptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if data, ok := pollEnterPayload(ctx, nfds); ok {
			res.ArgParts = append(res.ArgParts, formatPollfds(data, nfds, false))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfds))

	if ctx.SysName == "poll" {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[2])))
	} else {
		tptr := ctx.Args[2]
		if tptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			if data, ok := ppollTimeoutPayload(ctx); ok {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", tptr))
			}
		}
		res.ArgParts = append(res.ArgParts, "NULL") // sigmask
		res.ArgParts = append(res.ArgParts, "8")    // sigsetsize
	}

	if ctx.Ret == 0 {
		res.ReturnDesc = "Timeout"
	} else if ctx.Ret > 0 {
		if dataExit, ok := pollExitPayload(ctx, nfds); ok {
			res.ReturnDesc = formatPollfdsExit(dataExit, nfds)
		}
	}

	return res
}

func selectFdSetBytes(nfds int) int {
	if nfds <= 0 {
		return 0
	}
	size := (nfds + 7) / 8
	if size > fdSetPayloadSize {
		return fdSetPayloadSize
	}
	return size
}

func selectEnterFdSetPayload(ctx *Context, argIndex int, nfds int) ([]byte, bool) {
	size := selectFdSetBytes(nfds)
	if size == 0 {
		return nil, true
	}
	if data, ok := ctx.PayloadBytes(argIndex, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func selectExitFdSetPayload(ctx *Context, argIndex int, nfds int) ([]byte, bool) {
	size := selectFdSetBytes(nfds)
	if size == 0 {
		return nil, true
	}
	if data, ok := ctx.PayloadBytes(argIndex, PayloadDirectionOut); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func selectTimeoutPayload(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(4, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, 16)
	}
	return nil, false
}

func selectExitTimeoutPayload(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(4, PayloadDirectionOut); ok {
		return boundedBpfStructData(data, 16)
	}
	return nil, false
}

func pollPayloadSize(nfds int) int {
	if nfds <= 0 {
		return 0
	}
	if nfds > pollPayloadLimit/pollFdSize {
		return pollPayloadLimit
	}
	return nfds * pollFdSize
}

func pollEnterPayload(ctx *Context, nfds int) ([]byte, bool) {
	size := pollPayloadSize(nfds)
	if size == 0 {
		return nil, true
	}
	if data, ok := ctx.PayloadStruct(0, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func pollExitPayload(ctx *Context, nfds int) ([]byte, bool) {
	size := pollPayloadSize(nfds)
	if size == 0 {
		return nil, true
	}
	if data, ok := ctx.PayloadStruct(0, PayloadDirectionOut); ok {
		return boundedBpfStructData(data, size)
	}
	return nil, false
}

func ppollTimeoutPayload(ctx *Context) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(2, PayloadDirectionIn); ok {
		return boundedBpfStructData(data, 16)
	}
	return nil, false
}

func formatPollfds(data []byte, nfds int, hasExitData bool) string {
	parts := []string{}
	limit := 16
	for i := 0; i < nfds && i < limit; i++ {
		off := i * 8
		if len(data) < off+8 {
			break
		}
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := binary.LittleEndian.Uint16(data[off+4 : off+6])

		if fd < 0 {
			parts = append(parts, fmt.Sprintf("{fd=%d}", fd))
		} else {
			s := fmt.Sprintf("{fd=%d, events=%s", fd, meta.DecodeFlags(uint64(events), "pollflags"))
			// Explicitly ignore revents in input array
			s += "}"
			parts = append(parts, s)
		}
	}
	if nfds > limit {
		parts = append(parts, "...")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatPollfdsExit(dataExit []byte, nfds int) string {
	parts := []string{}
	for i := 0; i < nfds; i++ {
		off := i * 8
		if len(dataExit) < off+8 {
			break
		}
		fd := int32(binary.LittleEndian.Uint32(dataExit[off : off+4]))
		revents := binary.LittleEndian.Uint16(dataExit[off+6 : off+8])
		if revents != 0 {
			parts = append(parts, fmt.Sprintf("{fd=%d, revents=%s}", fd, meta.DecodeFlags(uint64(revents), "pollflags")))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
