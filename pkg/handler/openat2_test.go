package handler

import (
	"encoding/binary"
	"errors"
	"testing"

	"strace-go/pkg/event"
)

type openHowMemoryReader struct {
	data  []byte
	reads int
}

func (r *openHowMemoryReader) Read(int, uint64, int) ([]byte, error) {
	r.reads++
	if r.data == nil {
		return nil, errors.New("unreadable address")
	}
	return append([]byte(nil), r.data...), nil
}

func (r *openHowMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func TestDecodeOpenHowIgnoresLegacyEnterSnapshot(t *testing.T) {
	reader := &openHowMemoryReader{data: openHowBytes(0, 0, 0)}
	decoder := event.NewDecoder()

	ctx := openHowContext(reader, decoder, openHowBytes(0, 0, 0), uint64(openHowMinSize))
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if ok {
		t.Fatalf("decodeOpenHow() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeOpenHowUsesPayloadStructSection(t *testing.T) {
	reader := &openHowMemoryReader{data: openHowBytes(0, 0, 0)}
	decoder := event.NewDecoder()

	ctx := openHowContext(reader, decoder, nil, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data:      openHowBytes(0, 0, 0),
		},
	}
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if !ok || got != "{flags=O_RDONLY, resolve=0}" {
		t.Fatalf("decodeOpenHow payload = %q, %v", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeOpenHowWithoutSnapshotDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &openHowMemoryReader{data: openHowBytes(0, 0, 0)}
	decoder := event.NewDecoder()

	ctx := openHowContext(reader, decoder, nil, uint64(openHowMinSize))
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if ok {
		t.Fatalf("decodeOpenHow() = %q, want fallback to pointer formatting", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestDecodeOpenHowDoesNotUseLegacyMemoryFallback(t *testing.T) {
	reader := &openHowMemoryReader{data: openHowBytes(0, 0, 0)}
	decoder := event.NewDecoder()

	ctx := openHowContext(reader, decoder, nil, uint64(openHowMinSize))
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if ok {
		t.Fatalf("decodeOpenHow() = %q, want fallback to pointer formatting", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func openHowContext(reader *openHowMemoryReader, decoder *event.Decoder, snapshot []byte, size uint64) *Context {
	buf := make([]byte, openHowSnapshotOffset+openHowSnapshotMax)
	dataLen := uint32(0)
	if snapshot != nil {
		copy(buf[openHowSnapshotOffset:], snapshot)
		dataLen = uint32(openHowSnapshotOffset + len(snapshot))
	}
	return &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{^uint64(99), 0x1000, 0x2000, size},
		ProbeRetEnter: 0,
		DataLen:       dataLen,
		StrArgBuf:     buf,
		Decoder:       decoder,
	}
}

func openHowBytes(flags uint64, mode uint64, resolve uint64) []byte {
	data := make([]byte, openHowMinSize)
	binary.LittleEndian.PutUint64(data[0:8], flags)
	binary.LittleEndian.PutUint64(data[8:16], mode)
	binary.LittleEndian.PutUint64(data[16:24], resolve)
	return data
}
