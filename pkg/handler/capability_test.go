package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func capHeaderBytes(version uint32, pid int32) []byte {
	data := make([]byte, capHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], version)
	binary.LittleEndian.PutUint32(data[4:8], uint32(pid))
	return data
}

func capDataBytes(words ...[3]uint32) []byte {
	data := make([]byte, len(words)*capDataSize)
	for i, word := range words {
		off := i * capDataSize
		binary.LittleEndian.PutUint32(data[off:off+4], word[0])
		binary.LittleEndian.PutUint32(data[off+4:off+8], word[1])
		binary.LittleEndian.PutUint32(data[off+8:off+12], word[2])
	}
	return data
}

func capabilityContext(syscall string, ret int64, header, capData []byte) *Context {
	ctx := &Context{
		Pid:           101,
		Tid:           101,
		TargetPid:     101,
		Ret:           ret,
		Args:          [6]uint64{0x1000, 0x2000},
		ProbeRetEnter: 0,
		ProbeRetExit:  0,
		Opts:          &cli.Options{VerboseDisabled: make(map[string]bool)},
		ScMeta: meta.Syscall{
			Name:     syscall,
			Args:     []string{"header", "data"},
			ArgTypes: []string{"cap_user_header_t", "cap_user_data_t"},
		},
	}
	if len(header) > 0 {
		ctx.PayloadSections = append(ctx.PayloadSections, PayloadSection{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1000,
			ProbeRet:  0,
			Data:      header,
		})
	}
	if len(capData) > 0 {
		direction := PayloadDirectionIn
		if syscall == "capget" {
			direction = PayloadDirectionOut
		}
		ctx.PayloadSections = append(ctx.PayloadSections, PayloadSection{
			Kind:      PayloadKindStruct,
			Direction: direction,
			ArgIndex:  1,
			UserPtr:   0x2000,
			ProbeRet:  0,
			Data:      capData,
		})
	}
	return ctx
}

func TestCapabilityHandlerFormatsCapsetV3Data(t *testing.T) {
	ctx := capabilityContext("capset", -1,
		capHeaderBytes(linuxCapabilityVersion3, 0),
		capDataBytes([3]uint32{2, 4, 0}, [3]uint32{8, 16, 0}))

	got := (&CapabilityHandler{}).Handle(ctx)
	wantHeader := "{version=_LINUX_CAPABILITY_VERSION_3, pid=0}"
	wantData := "{effective=1<<CAP_DAC_OVERRIDE|1<<CAP_WAKE_ALARM, permitted=1<<CAP_DAC_READ_SEARCH|1<<CAP_BLOCK_SUSPEND, inheritable=0}"
	if len(got.ArgParts) != 2 || got.ArgParts[0] != wantHeader || got.ArgParts[1] != wantData {
		t.Fatalf("capset args = %#v, want %#v", got.ArgParts, []string{wantHeader, wantData})
	}
}

func TestCapabilityHandlerFormatsCapsetV1Data(t *testing.T) {
	ctx := capabilityContext("capset", -1,
		capHeaderBytes(linuxCapabilityVersion1, 0),
		capDataBytes([3]uint32{2, 4, 0}))

	got := (&CapabilityHandler{}).Handle(ctx)
	wantData := "{effective=1<<CAP_DAC_OVERRIDE, permitted=1<<CAP_DAC_READ_SEARCH, inheritable=0}"
	if len(got.ArgParts) != 2 || got.ArgParts[1] != wantData {
		t.Fatalf("capset v1 data = %#v, want %q", got.ArgParts, wantData)
	}
}

func TestCapabilityHandlerUsesExitDataForCapget(t *testing.T) {
	ctx := capabilityContext("capget", 0,
		capHeaderBytes(linuxCapabilityVersion3, 0),
		capDataBytes([3]uint32{1, 0, 0}, [3]uint32{0, 0, 0}))

	got := (&CapabilityHandler{}).Handle(ctx)
	wantData := "{effective=1<<CAP_CHOWN, permitted=0, inheritable=0}"
	if len(got.ArgParts) != 2 || got.ArgParts[1] != wantData {
		t.Fatalf("capget data = %#v, want %q", got.ArgParts, wantData)
	}
}

func TestCapabilityHandlerUsesPayloadStructSectionsForCapget(t *testing.T) {
	ctx := capabilityContext("capget", 0, nil, nil)
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1000,
			Data:      capHeaderBytes(linuxCapabilityVersion3, 0),
		},
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionOut,
			ArgIndex:  1,
			UserPtr:   0x2000,
			Data:      capDataBytes([3]uint32{1, 0, 0}, [3]uint32{0, 0, 0}),
		},
	}

	got := (&CapabilityHandler{}).Handle(ctx)
	wantData := "{effective=1<<CAP_CHOWN, permitted=0, inheritable=0}"
	if len(got.ArgParts) != 2 || got.ArgParts[1] != wantData {
		t.Fatalf("capget payload data = %#v, want %q", got.ArgParts, wantData)
	}
}

func TestCapabilityHandlerUsesPayloadStructSectionsForCapset(t *testing.T) {
	ctx := capabilityContext("capset", -1, nil, nil)
	ctx.PayloadSections = []PayloadSection{
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  0,
			UserPtr:   0x1000,
			Data:      capHeaderBytes(linuxCapabilityVersion3, 0),
		},
		{
			Kind:      PayloadKindStruct,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x2000,
			Data:      capDataBytes([3]uint32{2, 4, 0}, [3]uint32{8, 16, 0}),
		},
	}

	got := (&CapabilityHandler{}).Handle(ctx)
	wantData := "{effective=1<<CAP_DAC_OVERRIDE|1<<CAP_WAKE_ALARM, permitted=1<<CAP_DAC_READ_SEARCH|1<<CAP_BLOCK_SUSPEND, inheritable=0}"
	if len(got.ArgParts) != 2 || got.ArgParts[1] != wantData {
		t.Fatalf("capset payload data = %#v, want %q", got.ArgParts, wantData)
	}
}

func TestCapabilityHandlerIgnoresLegacyFixedSnapshot(t *testing.T) {
	ctx := capabilityContext("capset", -1, nil, nil)

	got := (&CapabilityHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 || got.ArgParts[0] != "0x1000" || got.ArgParts[1] != "0x2000" {
		t.Fatalf("legacy fixed snapshot args = %#v, want raw pointers", got.ArgParts)
	}
}

func TestCapabilityHandlerKeepsPointerWhenHeaderProbeFails(t *testing.T) {
	ctx := capabilityContext("capget", -1,
		capHeaderBytes(0, 0),
		capDataBytes([3]uint32{1, 0, 0}, [3]uint32{0, 0, 0}))
	ctx.ProbeRetEnter = -2

	got := (&CapabilityHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 || got.ArgParts[0] != "0x1000" {
		t.Fatalf("header probe failure args = %#v, want header pointer", got.ArgParts)
	}
}

func TestCapabilityHandlerUnknownVersionKeepsDataPointer(t *testing.T) {
	ctx := capabilityContext("capset", -1,
		capHeaderBytes(0xbadc0ded, -1576685468),
		capDataBytes([3]uint32{2, 4, 0}))

	got := (&CapabilityHandler{}).Handle(ctx)
	wantHeader := "{version=0xbadc0ded /* _LINUX_CAPABILITY_VERSION_??? */, pid=-1576685468}"
	if len(got.ArgParts) != 2 || got.ArgParts[0] != wantHeader || got.ArgParts[1] != "0x2000" {
		t.Fatalf("unknown version args = %#v", got.ArgParts)
	}
}

func TestCapabilityHandlerHonorsVerboseDisabled(t *testing.T) {
	ctx := capabilityContext("capget", 0,
		capHeaderBytes(linuxCapabilityVersion3, 0),
		capDataBytes([3]uint32{1, 0, 0}, [3]uint32{0, 0, 0}))
	ctx.Opts.VerboseDisabled["capget"] = true

	got := (&CapabilityHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 || got.ArgParts[0] != "0x1000" || got.ArgParts[1] != "0x2000" {
		t.Fatalf("verbose disabled args = %#v, want raw pointers", got.ArgParts)
	}
}
