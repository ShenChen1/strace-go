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
	fdSetSnapshotSize     = 128
	selectTimeoutOffset   = 384
	selectExitOffset      = BpfExitArgOffset
	selectExitTimeoutOff  = 1408
	pollFdSize            = 8
	pollSnapshotLimit     = 512
	ppollTimeoutOffset    = BpfMiscArgOffset
	selectFdSetArgBase    = 1
	selectFdSetArgLast    = 3
	selectFdSetArgSpacing = 128
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

		if data, ok := selectEnterFdSetSnapshot(ctx, i, nfds); ok {
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

	if data, ok := ctx.EnterArgSnapshot(4, selectTimeoutOffset, 16); ok {
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

		if data, ok := selectExitFdSetSnapshot(ctx, i, nfds); ok {
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
		if data, ok := ctx.ExitSnapshot(selectExitTimeoutOff, 16); ok {
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
		if data, ok := pollEnterSnapshot(ctx, nfds); ok {
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
			if data, ok := ctx.EnterArgSnapshot(2, ppollTimeoutOffset, 16); ok {
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
		if dataExit, ok := pollExitSnapshot(ctx, nfds); ok {
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
	if size > fdSetSnapshotSize {
		return fdSetSnapshotSize
	}
	return size
}

func selectFdSetOffset(argIndex int) int {
	return (argIndex - selectFdSetArgBase) * selectFdSetArgSpacing
}

func selectEnterFdSetSnapshot(ctx *Context, argIndex int, nfds int) ([]byte, bool) {
	size := selectFdSetBytes(nfds)
	if size == 0 {
		return nil, true
	}
	return ctx.EnterArgSnapshot(argIndex, selectFdSetOffset(argIndex), size)
}

func selectExitFdSetSnapshot(ctx *Context, argIndex int, nfds int) ([]byte, bool) {
	size := selectFdSetBytes(nfds)
	if size == 0 {
		return nil, true
	}
	offset := selectExitOffset + selectFdSetOffset(argIndex)
	return ctx.ExitSnapshot(offset, size)
}

func pollSnapshotSize(nfds int) int {
	if nfds <= 0 {
		return 0
	}
	if nfds > pollSnapshotLimit/pollFdSize {
		return pollSnapshotLimit
	}
	return nfds * pollFdSize
}

func pollEnterSnapshot(ctx *Context, nfds int) ([]byte, bool) {
	size := pollSnapshotSize(nfds)
	if size == 0 {
		return nil, true
	}
	return ctx.EnterArgSnapshot(0, BpfEnterArgOffset, size)
}

func pollExitSnapshot(ctx *Context, nfds int) ([]byte, bool) {
	size := pollSnapshotSize(nfds)
	if size == 0 {
		return nil, true
	}
	return ctx.ExitSnapshot(BpfExitArgOffset, size)
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
