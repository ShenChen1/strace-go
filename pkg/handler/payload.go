package handler

import "strings"

// PayloadKind classifies a BPF-captured user memory payload.
type PayloadKind string

const (
	PayloadKindString   PayloadKind = "string"
	PayloadKindBytes    PayloadKind = "bytes"
	PayloadKindStruct   PayloadKind = "struct"
	PayloadKindIovec    PayloadKind = "iovec"
	PayloadKindSockaddr PayloadKind = "sockaddr"
	PayloadKindExecArgs PayloadKind = "exec_args"
	PayloadKindCmsg     PayloadKind = "cmsg"
	PayloadKindFDState  PayloadKind = "fd_state"
	PayloadKindFDPath   PayloadKind = "fd_path"
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
	UserPtr   uint64
	UserLen   uint32
	CopiedLen uint32
	ProbeRet  int32
	Data      []byte
}

// PayloadBytes returns successfully captured byte payload data for one argument.
func (ctx *Context) PayloadBytes(argIndex int, direction PayloadDirection) ([]byte, bool) {
	return ctx.payloadData(argIndex, PayloadKindBytes, direction)
}

// PayloadString decodes a successfully captured string payload for one argument.
func (ctx *Context) PayloadString(argIndex int, direction PayloadDirection, ptr uint64, limit int) (string, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex != argIndex || section.Kind != PayloadKindString ||
			section.Direction != direction || section.ProbeRet != 0 || len(section.Data) == 0 {
			continue
		}
		text := ctx.Decoder.DecodeString(ctx.Pid, ptr, section.Data, section.ProbeRet, ctx.SysName, limit)
		if section.UserLen > section.CopiedLen && !strings.HasSuffix(text, "...") && !strings.HasPrefix(text, "0x") {
			text += "..."
		}
		return text, true
	}
	return "", false
}

// PayloadIovec returns a captured struct iovec array prefix for one argument.
func (ctx *Context) PayloadIovec(argIndex int, direction PayloadDirection) ([]byte, bool) {
	return ctx.payloadData(argIndex, PayloadKindIovec, direction)
}

// PayloadStruct returns a captured struct payload for one argument.
func (ctx *Context) PayloadStruct(argIndex int, direction PayloadDirection) ([]byte, bool) {
	return ctx.payloadData(argIndex, PayloadKindStruct, direction)
}

// PayloadExecArgs returns a captured exec argv/envp snapshot.
func (ctx *Context) PayloadExecArgs(argIndex int) ([]byte, bool) {
	return ctx.payloadData(argIndex, PayloadKindExecArgs, PayloadDirectionIn)
}

// PayloadCmsg returns a captured msghdr ancillary data buffer for one argument.
func (ctx *Context) PayloadCmsg(argIndex int, direction PayloadDirection) ([]byte, bool) {
	return ctx.payloadData(argIndex, PayloadKindCmsg, direction)
}

func (ctx *Context) payloadData(argIndex int, kind PayloadKind, direction PayloadDirection) ([]byte, bool) {
	for _, section := range ctx.PayloadSections {
		if section.ArgIndex == argIndex && section.Kind == kind &&
			section.Direction == direction && section.ProbeRet == 0 && len(section.Data) > 0 {
			return section.Data, true
		}
	}
	return nil, false
}
