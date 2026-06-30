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
