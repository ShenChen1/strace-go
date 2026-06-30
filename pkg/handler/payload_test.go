package handler

import "testing"

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
