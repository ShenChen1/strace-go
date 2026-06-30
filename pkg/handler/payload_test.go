package handler

import (
	"testing"

	"strace-go/pkg/event"
)

func TestContextSectionFindsPayloadByArgumentAndKind(t *testing.T) {
	want := PayloadSection{
		Kind:      PayloadKindBytes,
		Direction: PayloadDirectionIn,
		ArgIndex:  1,
		UserPtr:   0x2000,
		UserLen:   5,
		CopiedLen: 5,
		Data:      []byte("hello"),
	}
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, ArgIndex: 0, Data: []byte("path")},
			want,
		},
	}

	got, ok := ctx.Section(1, PayloadKindBytes)
	if !ok {
		t.Fatal("Section(1, bytes) returned no payload")
	}
	if got.Kind != want.Kind || got.Direction != want.Direction || got.ArgIndex != want.ArgIndex ||
		got.UserPtr != want.UserPtr || got.UserLen != want.UserLen || string(got.Data) != string(want.Data) {
		t.Fatalf("Section(1, bytes) = %+v, want %+v", got, want)
	}
}

func TestContextSectionRejectsKindMismatch(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, ArgIndex: 1, Data: []byte("hello")},
		},
	}

	if got, ok := ctx.Section(1, PayloadKindBytes); ok {
		t.Fatalf("Section(1, bytes) = %+v, want no match", got)
	}
}

func TestContextPayloadBytesRejectsFailedOrWrongDirectionSection(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("in")},
			{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: -14, Data: []byte("out")},
		},
	}

	if data, ok := ctx.PayloadBytes(1, PayloadDirectionOut); ok {
		t.Fatalf("PayloadBytes wrong direction = %q, want no match", string(data))
	}
	if data, ok := ctx.PayloadBytes(2, PayloadDirectionOut); ok {
		t.Fatalf("PayloadBytes failed probe = %q, want no match", string(data))
	}
}

func TestContextPayloadBytesMatchesDirectionAfterEarlierSection(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("in")},
			{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: []byte("out")},
		},
	}

	data, ok := ctx.PayloadBytes(1, PayloadDirectionOut)
	if !ok || string(data) != "out" {
		t.Fatalf("PayloadBytes out = %q, %v; want later out section", string(data), ok)
	}
}

func TestContextPayloadStringRejectsFailedOrWrongDirectionSection(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("in\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: -14, Data: []byte("out\x00")},
		},
	}

	if data, ok := ctx.PayloadString(1, PayloadDirectionOut, 0x1000, 0); ok {
		t.Fatalf("PayloadString wrong direction = %q, want no match", data)
	}
	if data, ok := ctx.PayloadString(2, PayloadDirectionOut, 0x2000, 0); ok {
		t.Fatalf("PayloadString failed probe = %q, want no match", data)
	}
}

func TestContextPayloadStringMatchesDirectionAfterEarlierSection(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindString, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("in\x00")},
			{Kind: PayloadKindString, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: []byte("out\x00")},
		},
		Decoder: event.NewDecoder(),
	}

	data, ok := ctx.PayloadString(1, PayloadDirectionOut, 0x1000, 0)
	if !ok || data != `"out"` {
		t.Fatalf("PayloadString out = %q, %v; want later out section", data, ok)
	}
}
