package handler

import "testing"

func newSockoptPayloadContext(name string) *Context {
	ctx := newNetworkPolicyContext(nil, name)
	ctx.Args = [6]uint64{3, 1, 2, 0x6000, 4}
	ctx.Ret = 0
	return ctx
}

func TestNetworkSetsockoptUsesInOptvalSnapshot(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserLen: 4, ProbeRet: 0, Data: uint32Bytes(1)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[1]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [1]", got, ok)
	}
}

func TestNetworkGetsockoptUsesOutOptvalSnapshot(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 3, UserLen: 4, ProbeRet: 0, Data: uint32Bytes(2)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[2]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [2]", got, ok)
	}
}

func TestNetworkGetsockoptLenUsesEnterAndExitSnapshots(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.Args[4] = 0x7000
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: uint32Bytes(5)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: uint32Bytes(4)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 4, "optlen", ctx.Args[4])
	if !ok || got != "[5 => 4]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [5 => 4]", got, ok)
	}
}

func TestNetworkSetsockoptFormatsSignedWordOptlen(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[4] = 0xdefaced00000005

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 4, "optlen", ctx.Args[4])
	if !ok || got != "5" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want 5", got, ok)
	}
}

func TestNetworkGetsockoptPreservesUnknownFiveByteSnapshot(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.Args[2] = 20
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 3, UserLen: 5, ProbeRet: 0, Data: []byte{0, 0, 0, 0, 0}},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != `"\0\0\0\0\0"` {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want five-byte snapshot", got, ok)
	}
}

func TestNetworkSockoptDecodesTxrehashSnapshot(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[2] = 74
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserLen: 4, ProbeRet: 0, Data: uint32Bytes(1)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[SOCK_TXREHASH_ENABLED]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want txrehash xlat", got, ok)
	}
}

func TestNetworkSockoptDecodesTxrehashDisabled(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[2] = 74
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserLen: 4, ProbeRet: 0, Data: uint32Bytes(0)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[SOCK_TXREHASH_DISABLED]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want disabled txrehash xlat", got, ok)
	}
}

func TestNetworkSockoptUsesNetlinkOptionXlat(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[1] = 270
	ctx.Args[2] = 1

	got, ok := (&NetworkHandler{}).formatSockopt(ctx, "optname", ctx.Args[2])
	if !ok || got != "NETLINK_ADD_MEMBERSHIP" {
		t.Fatalf("formatSockopt() = %q, %v; want NETLINK_ADD_MEMBERSHIP", got, ok)
	}
}

func TestNetworkSockoptRecognizesSOINQAsFixedInt(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[2] = 84
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserLen: 5, CopiedLen: 4, ProbeRet: 0, Data: uint32Bytes(1)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[1]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [1]", got, ok)
	}
}

func TestNetworkSockoptFormatsShortNetlinkMembershipArray(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.Args[1] = 270
	ctx.Args[2] = 9
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 3, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte{0, 0, 0}},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want []", got, ok)
	}
}

func TestNetworkSockoptFormatsShortNetlinkMembershipWithoutOutSnapshot(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.Args[1] = 270
	ctx.Args[2] = 9
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 4, UserLen: 4, CopiedLen: 4, ProbeRet: 0, Data: uint32Bytes(3)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want []", got, ok)
	}
}

func TestNetworkSockoptFormatsNetlinkMembershipArray(t *testing.T) {
	ctx := newSockoptPayloadContext("getsockopt")
	ctx.Args[1] = 270
	ctx.Args[2] = 9
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 3, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: append(uint32Bytes(1), uint32Bytes(2)...)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[1, 2]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [1, 2]", got, ok)
	}
}

func TestNetworkSockoptFormatsNetlinkMembershipSetAsInt(t *testing.T) {
	ctx := newSockoptPayloadContext("setsockopt")
	ctx.Args[1] = 270
	ctx.Args[2] = 9
	ctx.Args[4] = 5
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 3, UserLen: 5, CopiedLen: 4, ProbeRet: 0, Data: uint32Bytes(1)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 3, "optval", ctx.Args[3])
	if !ok || got != "[1]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want [1]", got, ok)
	}
}
