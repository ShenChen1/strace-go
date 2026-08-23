package handler

import (
	"encoding/binary"
	"fmt"
	"strings"

	"strace-go/pkg/format"
)

func registerBuiltinSelect(r *Registry) {
	h := &SelectHandler{}
	r.Register("select", h)
	r.Register("_newselect", h)
	r.Register("pselect6", h)

	ph := &PollHandler{}
	r.Register("poll", ph)
	r.Register("ppoll", ph)
}

type SelectHandler struct{}

const (
	fdSetPayloadSize   = 128
	pollFdSize         = 8
	pollPayloadLimit   = 512
	selectFdSetArgBase = 1
	selectFdSetArgLast = 3
	pselect6SigmaskArg = 6
)

func (h *SelectHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfds := int(int32(ctx.Args[0]))
	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfds))

	h.formatSelectFdSets(ctx, nfds, &res)
	h.formatSelectTimeout(ctx, &res)
	if ctx.SysName == "pselect6" {
		h.formatPselect6Sigmask(ctx, &res)
	}

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
		if ctx.SysName == "pselect6" {
			res.ArgParts = append(res.ArgParts, format.Timespec(data))
		} else {
			res.ArgParts = append(res.ArgParts, format.Timeval(data))
		}
	} else {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", tptr))
	}
}

func (h *SelectHandler) formatPselect6Sigmask(ctx *Context, res *Result) {
	ptr := ctx.Args[5]
	if ptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
		return
	}

	wrapper, ok := ctx.PayloadStruct(5, PayloadDirectionIn)
	if !ok || len(wrapper) < 16 {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		return
	}

	maskPtr := binary.LittleEndian.Uint64(wrapper[0:8])
	sigsetsize := binary.LittleEndian.Uint64(wrapper[8:16])
	sigmask := fmt.Sprintf("%#x", maskPtr)
	if sigsetsize > 0 && sigsetsize <= 8 {
		if mask, ok := pselect6SigmaskSnapshot(ctx, int(sigsetsize)); ok {
			if decoded := format.Sigset(mask); decoded != "" {
				sigmask = decoded
			}
		}
	}
	res.ArgParts = append(
		res.ArgParts,
		fmt.Sprintf("{sigmask=%s, sigsetsize=%d}", sigmask, sigsetsize),
	)
}

func (h *SelectHandler) formatSelectExit(ctx *Context, nfds int, res *Result) {
	outParts := []string{}
	setNames := []string{"in", "out", "exc"}
	hasExitFdSetPayload := false
	for i := selectFdSetArgBase; i <= selectFdSetArgLast; i++ {
		ptr := ctx.Args[i]
		if ptr == 0 {
			continue
		}

		if data, ok := selectExitFdSetPayload(ctx, i, nfds); ok {
			hasExitFdSetPayload = true
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
			if ctx.SysName == "pselect6" {
				outParts = append(outParts, "left "+format.Timespec(data))
			} else {
				outParts = append(outParts, "left "+format.Timeval(data))
			}
		}
	}
	if len(outParts) > 0 {
		res.ReturnDesc = strings.Join(outParts, ", ")
	} else if hasExitFdSetPayload {
		res.ShowEmptyReturnDesc = true
	}
}

type PollHandler struct{}

func (h *PollHandler) Handle(ctx *Context) Result {
	res := Result{}
	nfdsValue := pollNfdsValue(ctx)
	nfds := pollNfdsInt(nfdsValue)
	ptr := ctx.Args[0]

	if ptr == 0 {
		res.ArgParts = append(res.ArgParts, "NULL")
	} else {
		if section, ok := pollPayloadSection(ctx, PayloadDirectionIn, nfds); ok {
			res.ArgParts = append(res.ArgParts, formatPollfds(ctx, section, nfds, pollDisplayLimit(ctx)))
		} else {
			res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", ptr))
		}
	}

	res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", nfdsValue))

	if ctx.SysName == "poll" {
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", int32(ctx.Args[2])))
	} else {
		tptr := ctx.Args[2]
		if tptr == 0 {
			res.ArgParts = append(res.ArgParts, "NULL")
		} else {
			if data, ok := ppollTimeoutPayload(ctx, PayloadDirectionIn); ok {
				res.ArgParts = append(res.ArgParts, format.Timespec(data))
			} else {
				res.ArgParts = append(res.ArgParts, fmt.Sprintf("%#x", tptr))
			}
		}
		res.ArgParts = append(res.ArgParts, ppollSigmask(ctx))
		res.ArgParts = append(res.ArgParts, fmt.Sprintf("%d", ctx.Args[4]))
	}

	if ctx.Ret == 0 {
		res.ReturnDesc = "Timeout"
	} else if ctx.Ret > 0 {
		if dataExit, ok := pollExitPayload(ctx, nfds); ok {
			res.ReturnDesc = formatPollfdsExit(ctx, dataExit, nfds, pollDisplayLimit(ctx))
		}
	}
	if ctx.SysName == "ppoll" && ctx.Ret > 0 {
		if data, ok := ppollTimeoutPayload(ctx, PayloadDirectionOut); ok {
			if res.ReturnDesc != "" {
				res.ReturnDesc += ", "
			}
			res.ReturnDesc += "left " + format.Timespec(data)
		}
	}

	return res
}

func pollNfdsValue(ctx *Context) uint64 {
	if ctx.SysName == "ppoll" {
		return uint64(uint32(ctx.Args[1]))
	}
	return ctx.Args[1]
}

func pollNfdsInt(nfds uint64) int {
	if nfds > uint64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(nfds)
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
	if nfds < 0 {
		return nil, false
	}
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
	if nfds < 0 {
		return nil, false
	}
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

func pselect6SigmaskSnapshot(ctx *Context, size int) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(pselect6SigmaskArg, PayloadDirectionIn); ok && len(data) >= size {
		return data[:size], true
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

func pollPayloadSection(ctx *Context, direction PayloadDirection, nfds int) (PayloadSection, bool) {
	size := pollPayloadSize(nfds)
	if size == 0 {
		return PayloadSection{}, true
	}
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex != 0 || section.Kind != PayloadKindStruct ||
			section.Direction != direction || section.ProbeRet != 0 || len(section.Data) == 0 {
			continue
		}
		if data, ok := boundedBpfStructData(section.Data, size); ok {
			section.Data = data
			return section, true
		}
	}
	return PayloadSection{}, false
}

func pollEnterPayload(ctx *Context, nfds int) ([]byte, bool) {
	section, ok := pollPayloadSection(ctx, PayloadDirectionIn, nfds)
	if !ok {
		return nil, false
	}
	return section.Data, true
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

func ppollTimeoutPayload(ctx *Context, direction PayloadDirection) ([]byte, bool) {
	if data, ok := ctx.PayloadStruct(2, direction); ok {
		return boundedBpfStructData(data, 16)
	}
	return nil, false
}

func ppollSigmask(ctx *Context) string {
	ptr := ctx.Args[3]
	if ptr == 0 {
		return "NULL"
	}
	if data, ok := ctx.PayloadStruct(3, PayloadDirectionIn); ok {
		return format.Sigset(data)
	}
	return fmt.Sprintf("%#x", ptr)
}

func pollDisplayLimit(ctx *Context) int {
	if ctx.Opts != nil && ctx.Opts.VerboseValue() {
		return pollPayloadLimit / pollFdSize
	}
	if ctx.Opts != nil && ctx.Opts.StringLimitValue() >= 0 {
		return ctx.Opts.StringLimitValue()
	}
	return 16
}

func formatPollfds(ctx *Context, section PayloadSection, nfds int, displayLimit int) string {
	if nfds <= 0 {
		return "[]"
	}
	if displayLimit <= 0 {
		return "[...]"
	}
	parts := []string{}
	data := section.Data
	for i := 0; i < nfds && i < displayLimit; i++ {
		off := i * 8
		if len(data) < off+8 {
			break
		}
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := binary.LittleEndian.Uint16(data[off+4 : off+6])

		if fd < 0 {
			parts = append(parts, fmt.Sprintf("{fd=%d}", fd))
		} else {
			s := fmt.Sprintf("{fd=%d, events=%s", fd, decodeFlags(ctx, uint64(events), "pollflags"))
			// Explicitly ignore revents in input array
			s += "}"
			parts = append(parts, s)
		}
	}
	if pollSectionNeedsMarker(section, nfds) {
		nextPtr := section.UserPtr + uint64(len(data))
		parts = append(parts, fmt.Sprintf("... /* %#x */", nextPtr))
	} else if nfds > displayLimit {
		parts = append(parts, "...")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pollSectionNeedsMarker(section PayloadSection, nfds int) bool {
	if section.UserPtr == 0 || section.UserLen == 0 || section.CopiedLen >= section.UserLen {
		return false
	}
	wantBytes := pollPayloadSize(nfds)
	return len(section.Data) < wantBytes
}

func formatPollfdsExit(ctx *Context, dataExit []byte, nfds int, displayLimit int) string {
	if nfds <= 0 {
		return ""
	}
	if displayLimit <= 0 {
		return "[...]"
	}
	parts := []string{}
	for i := 0; i < nfds; i++ {
		off := i * 8
		if len(dataExit) < off+8 {
			break
		}
		fd := int32(binary.LittleEndian.Uint32(dataExit[off : off+4]))
		revents := binary.LittleEndian.Uint16(dataExit[off+6 : off+8])
		if revents != 0 {
			parts = append(parts, fmt.Sprintf("{fd=%d, revents=%s}", fd, decodeFlags(ctx, uint64(revents), "pollflags")))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > displayLimit {
		parts = append(parts[:displayLimit], "...")
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
