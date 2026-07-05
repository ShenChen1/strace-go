package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
)

func TestDecodeOpenHowIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.ProbeRetEnter = 0
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if ok {
		t.Fatalf("decodeOpenHow() = %q, want pointer fallback", got)
	}
}

func TestDecodeOpenHowUsesPayloadStructSection(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
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
}

func TestDecodeOpenHowFallsBackWithoutPayloadSection(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if ok {
		t.Fatalf("decodeOpenHow() = %q, want fallback to pointer formatting", got)
	}
}

func openHowContext(decoder *event.Decoder, size uint64) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		Args:          [6]uint64{^uint64(99), 0x1000, 0x2000, size},
		ProbeRetEnter: -1,
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
