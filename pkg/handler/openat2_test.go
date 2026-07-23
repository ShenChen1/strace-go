package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
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

func TestDecodeOpenHowMarksMissingExtensionUnknown(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize+8))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			UserLen:   uint32(openHowMinSize + 8),
			CopiedLen: uint32(openHowMinSize),
			ProbeRet:  0,
			Data:      openHowBytes(0, 0, 0),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	if !ok || got != "{flags=O_RDONLY, resolve=0, ???}" {
		t.Fatalf("decodeOpenHow partial extension = %q, %v", got, ok)
	}
}

func TestDecodeOpenHowPreserves64BitFlagsAndMode(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data: openHowBytes(
				0xdeadface80000000,
				0777,
				0xdec0dedbeeffffc0,
			),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	want := "{flags=O_RDONLY|0xdeadface80000000, mode=0777, resolve=0xdec0dedbeeffffc0 /* RESOLVE_??? */}"
	if !ok || got != want {
		t.Fatalf("decodeOpenHow 64-bit fields = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeOpenHowPrintsNonZeroModeWithoutCreate(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data: openHowBytes(
				0x8002,
				0xbadc0dedfacebeef,
				1,
			),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	want := "{flags=O_RDWR|O_LARGEFILE, mode=01353340336677263537357, resolve=RESOLVE_NO_XDEV}"
	if !ok || got != want {
		t.Fatalf("decodeOpenHow nonzero mode = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeOpenHowPrintsZeroModeWithModeFlags(t *testing.T) {
	decoder := event.NewDecoder()

	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data:      openHowBytes(0x40, 0, 0),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	want := "{flags=O_RDONLY|O_CREAT, mode=000, resolve=0}"
	if !ok || got != want {
		t.Fatalf("decodeOpenHow zero mode = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeOpenHowRawXlatUsesFull64BitValues(t *testing.T) {
	old := meta.XlatFormat
	meta.XlatFormat = "raw"
	defer func() { meta.XlatFormat = old }()

	decoder := event.NewDecoder()
	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data:      openHowBytes(0xdeadface80000000, 0, 0xfeedfacedcaffec0),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	want := "{flags=0xdeadface80000000, resolve=0xfeedfacedcaffec0}"
	if !ok || got != want {
		t.Fatalf("decodeOpenHow raw xlat = %q, %v; want %q", got, ok, want)
	}
}

func TestDecodeOpenHowVerboseXlatDoesNotWrapUnknownComments(t *testing.T) {
	old := meta.XlatFormat
	meta.XlatFormat = "verbose"
	defer func() { meta.XlatFormat = old }()

	decoder := event.NewDecoder()
	ctx := openHowContext(decoder, uint64(openHowMinSize))
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  2,
			UserPtr:   0x2000,
			Data:      openHowBytes(0x410003, 0, 0xdec0dedbeeffffc0),
		},
	}

	got, ok := decodeOpenHow(ctx, 2, "struct open_how *", 0x2000)
	want := "{flags=0x410003 /* O_ACCMODE|O_TMPFILE */, mode=000, resolve=0xdec0dedbeeffffc0 /* RESOLVE_??? */}"
	if !ok || got != want {
		t.Fatalf("decodeOpenHow verbose unknown = %q, %v; want %q", got, ok, want)
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
