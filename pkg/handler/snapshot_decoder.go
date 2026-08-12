package handler

// SnapshotDecoder decodes memory captured at the BPF probe site.
type SnapshotDecoder interface {
	DecodeString(pid int, ptr uint64, bpfData []byte, probeRet int32, syscallName string, limit int) string
	EscapeMode() int
}
