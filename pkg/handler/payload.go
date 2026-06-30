package handler

// PayloadKind classifies a BPF-captured user memory payload.
type PayloadKind string

const (
	PayloadKindString   PayloadKind = "string"
	PayloadKindBytes    PayloadKind = "bytes"
	PayloadKindStruct   PayloadKind = "struct"
	PayloadKindIovec    PayloadKind = "iovec"
	PayloadKindSockaddr PayloadKind = "sockaddr"
	PayloadKindExecArgs PayloadKind = "exec_args"
)

// PayloadDirection records whether a payload was captured on syscall enter or exit.
type PayloadDirection string

const (
	PayloadDirectionIn  PayloadDirection = "in"
	PayloadDirectionOut PayloadDirection = "out"
)

// PayloadSection describes one semantic slice of BPF-captured user memory.
type PayloadSection struct {
	Kind      PayloadKind
	Direction PayloadDirection
	ArgIndex  int
	Offset    uint32
	UserPtr   uint64
	UserLen   uint32
	CopiedLen uint32
	ProbeRet  int32
	Data      []byte
}

// PayloadBytes returns successfully captured byte payload data for one argument.
func (ctx *Context) PayloadBytes(argIndex int, direction PayloadDirection) ([]byte, bool) {
	section, ok := ctx.Section(argIndex, PayloadKindBytes)
	if !ok || section.Direction != direction || section.ProbeRet != 0 || len(section.Data) == 0 {
		return nil, false
	}
	return section.Data, true
}

// PayloadString decodes a successfully captured string payload for one argument.
func (ctx *Context) PayloadString(argIndex int, direction PayloadDirection, ptr uint64, limit int) (string, bool) {
	section, ok := ctx.Section(argIndex, PayloadKindString)
	if !ok || section.Direction != direction || section.ProbeRet != 0 || len(section.Data) == 0 {
		return "", false
	}
	return ctx.Decoder.DecodeString(ctx.Pid, ptr, section.Data, section.ProbeRet, ctx.SysName, limit), true
}
