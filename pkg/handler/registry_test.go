package handler

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type registryTestHandler struct{}

func (registryTestHandler) Handle(*Context) Result {
	return Result{ReturnDesc: "registry"}
}

func TestNewRegistryIsolatesHandlerOverrides(t *testing.T) {
	first := NewRegistry()
	second := NewRegistry()
	marker := registryTestHandler{}

	first.Register("registry_only", marker)
	if got := first.Resolve("registry_only"); got != marker {
		t.Fatalf("first registry resolved %T, want test handler", got)
	}
	if got := second.Resolve("registry_only"); got == marker {
		t.Fatal("handler override leaked into second registry")
	}
	if got := NewRegistry().Resolve("registry_only"); got == marker {
		t.Fatal("handler override leaked into built-in registry")
	}
}

func TestDefaultHandlerUsesContextRegistryDecoders(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterPointerDecoder(
		"struct registry_test *",
		PointerDecoderFunc(func(*Context, int, string, string, uint64, *Result) (string, bool) {
			return "registry-decoder", true
		}),
	)
	ctx := &Context{
		Registry: registry,
		Decoder:  event.NewDecoder(),
		Opts:     &cli.Options{},
		ScMeta: meta.Syscall{
			Name:     "registry_test",
			Args:     []string{"value"},
			ArgTypes: []string{"struct registry_test *"},
		},
		Args: [6]uint64{0x1000},
	}

	got := (&DefaultHandler{}).Handle(ctx)
	if len(got.ArgParts) != 1 || got.ArgParts[0] != "registry-decoder" {
		t.Fatalf("decoded args = %v, want registry decoder", got.ArgParts)
	}
}

func TestRegistryHandleUsesSessionHandler(t *testing.T) {
	registry := NewRegistry()
	registry.Register("registry_test", registryTestHandler{})

	got := registry.Handle("registry_test", &Context{})
	if got.ReturnDesc != "registry" {
		t.Fatalf("result = %+v, want session handler result", got)
	}
}

func TestRegistryKeepsBuiltInDefaultHandler(t *testing.T) {
	registry := NewRegistry()
	if _, ok := registry.Default().(*DefaultHandler); !ok {
		t.Fatalf("default handler = %T, want *DefaultHandler", registry.Default())
	}
	if got := registry.Resolve("unknown"); got == nil {
		t.Fatal("unknown syscall did not resolve to built-in default")
	}
	if GetDefault() == nil {
		t.Fatal("built-in default handler is nil")
	}
}
