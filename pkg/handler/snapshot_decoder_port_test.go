package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

type snapshotDecoderTestStub struct {
	text       string
	escapeMode int
}

func (stub snapshotDecoderTestStub) DecodeString(int, uint64, []byte, int32, string, int) string {
	return stub.text
}

func (stub snapshotDecoderTestStub) EscapeMode() int {
	return stub.escapeMode
}

func TestContextDecoderUsesSnapshotDecoderPort(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "handler.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse handler.go: %v", err)
	}
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Context" {
			return true
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if name.Name != "Decoder" {
					continue
				}
				decoderType, ok := field.Type.(*ast.Ident)
				found = ok && decoderType.Name == "SnapshotDecoder"
			}
		}
		return false
	})
	if !found {
		t.Fatal("handler Context must depend on SnapshotDecoder")
	}
}

func TestPayloadStringUsesSnapshotDecoderPort(t *testing.T) {
	ctx := &Context{
		Pid:     7,
		SysName: "openat",
		Decoder: snapshotDecoderTestStub{text: "snapshot-text"},
		PayloadSections: []PayloadSection{{
			Kind:      PayloadKindString,
			Direction: PayloadDirectionIn,
			ArgIndex:  1,
			UserPtr:   0x1000,
			UserLen:   13,
			CopiedLen: 13,
			ProbeRet:  0,
			Data:      []byte("ignored"),
		}},
	}

	got, ok := ctx.PayloadString(1, PayloadDirectionIn, 0x1000, 0)
	if !ok || got != "snapshot-text" {
		t.Fatalf("PayloadString() = %q, %v; want snapshot-text, true", got, ok)
	}
}

func TestCmsgTextUsesSnapshotDecoderEscapeMode(t *testing.T) {
	ctx := &Context{Decoder: snapshotDecoderTestStub{escapeMode: 2}}
	got := formatCmsgText(ctx, []byte{'A', 1})
	if got != "\"\\x41\\x01\"" {
		t.Fatalf("formatCmsgText() = %q, want hex escaped bytes", got)
	}
}
