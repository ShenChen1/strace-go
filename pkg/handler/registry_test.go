package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type registryTestHandler struct{}

type registryPortTestStub struct {
	defaultHandler Handler
	pointerDecoder PointerDecoder
}

func (registryPortTestStub) Handle(string, *Context) Result {
	return Result{}
}

func (stub registryPortTestStub) Default() Handler {
	return stub.defaultHandler
}

func (stub registryPortTestStub) PointerDecoder(string) PointerDecoder {
	return stub.pointerDecoder
}

func (registryPortTestStub) StructDecoder(string) TypeDecoder {
	return nil
}

var builtinHandlerNames = []string{
	"io_setup", "io_destroy", "io_submit", "io_cancel", "io_getevents", "io_pgetevents", "io_pgetevents_time64",
	"arch_prctl", "bpf", "cachestat", "capget", "capset", "copy_file_range",
	"epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2", "fcntl", "fcntl64",
	"getdents", "getdents64", "mount", "umount2", "fsconfig", "futex",
	"get_robust_list", "set_robust_list", "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
	"process_vm_readv", "process_vm_writev", "vmsplice", "ioctl", "open_tree", "move_mount",
	"statmount", "listmount", "mount_setattr", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
	"accept", "accept4", "getsockname", "getpeername", "recvfrom", "sendto", "connect", "bind", "socket",
	"setsockopt", "getsockopt", "prctl", "clone3", "process_madvise", "quotactl", "quotactl_fd",
	"select", "_newselect", "pselect6", "poll", "ppoll", "sendfile",
	"rt_sigprocmask", "rt_sigaction", "rt_sigpending", "rt_sigsuspend", "signalfd", "signalfd4",
	"statx", "open", "openat", "mknod", "mknodat", "brk", "mremap",
	"adjtimex", "clock_adjtime", "clock_gettime", "clock_settime", "clock_getres", "waitid",
}

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

func TestDefaultHandlerAcceptsRegistryPort(t *testing.T) {
	ctx := &Context{
		Registry: registryPortTestStub{
			defaultHandler: &DefaultHandler{},
			pointerDecoder: PointerDecoderFunc(func(*Context, int, string, string, uint64, *Result) (string, bool) {
				return "port-decoder", true
			}),
		},
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{},
		ScMeta: meta.Syscall{
			Name:     "registry_port_test",
			Args:     []string{"value"},
			ArgTypes: []string{"struct registry_port *"},
		},
		Args: [6]uint64{0x1000},
	}

	got := handleDefaultWithCount(ctx, 1)
	if len(got.ArgParts) != 1 || got.ArgParts[0] != "port-decoder" {
		t.Fatalf("decoded args = %v, want registry port decoder", got.ArgParts)
	}
}

func TestDefaultHandlerWithoutRegistryDoesNotUseBuiltinPointerDecoder(t *testing.T) {
	ctx := &Context{
		Decoder: event.NewDecoder(),
		Meta:    meta.NewCatalog("abbrev"),
		Opts:    &cli.Options{},
		ScMeta: meta.Syscall{
			Name:     "write",
			Args:     []string{"fd", "buf", "count"},
			ArgTypes: []string{"int", "char *", "size_t"},
		},
		Args: [6]uint64{1, 0x1000, 5},
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				UserPtr:   0x1000,
				UserLen:   5,
				CopiedLen: 5,
				ProbeRet:  0,
				Data:      []byte("hello"),
			},
		},
	}

	got := (&DefaultHandler{}).Handle(ctx).ArgParts
	if len(got) != 3 || got[1] != "0x1000" {
		t.Fatalf("default handler without registry = %#v, want raw pointer fallback", got)
	}
}

func TestContextRegistryOwnershipHasNoBuiltinFallback(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "handler.go"))
	if err != nil {
		t.Fatalf("read handler.go: %v", err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"func (ctx *Context) registry()",
		"return builtinRegistry\n",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("handler.go still contains implicit registry fallback %q", forbidden)
		}
	}
}

func TestContextRegistryUsesPort(t *testing.T) {
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
				if name.Name != "Registry" {
					continue
				}
				registryType, ok := field.Type.(*ast.Ident)
				found = ok && registryType.Name == "RegistryPort"
			}
		}
		return false
	})
	if !found {
		t.Fatal("handler Context must depend on RegistryPort")
	}
}

func TestNewRegistryContainsBuiltinCatalog(t *testing.T) {
	registry := NewRegistry()
	defaultType := reflect.TypeOf(registry.Default())
	for _, name := range builtinHandlerNames {
		handler := registry.Resolve(name)
		if handler == nil {
			t.Fatalf("builtin handler %q is missing", name)
		}
		if reflect.TypeOf(handler) == defaultType {
			t.Fatalf("builtin handler %q resolved to default handler", name)
		}
	}
	if registry.PointerDecoder("char *") == nil {
		t.Fatal("builtin char pointer decoder is missing")
	}
	if registry.StructDecoder("struct stat *") == nil {
		t.Fatal("builtin stat decoder is missing")
	}
}

func TestHandlerRegistrationHasNoImplicitBootstrap(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	entries, err := os.ReadDir(filepath.Dir(currentFile))
	if err != nil {
		t.Fatalf("read handler directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		assertNoImplicitBootstrap(t, filepath.Join(filepath.Dir(currentFile), entry.Name()))
	}
}

func assertNoImplicitBootstrap(t *testing.T, path string) {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "init" {
			t.Fatalf("%s still declares init", path)
		}
	}
	forbidden := map[string]bool{
		"Get":                    true,
		"GetDefault":             true,
		"Register":               true,
		"RegisterPointerDecoder": true,
		"RegisterStructDecoder":  true,
		"SetDefault":             true,
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		identifier, ok := call.Fun.(*ast.Ident)
		if ok && forbidden[identifier.Name] {
			t.Fatalf("%s calls package-level bootstrap API %s", path, identifier.Name)
		}
		return true
	})
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
	if NewRegistry().Default() == nil {
		t.Fatal("built-in default handler is nil")
	}
}
