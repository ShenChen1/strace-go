package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/handler"
)

func TestTextRendererUsesNarrowTimeAndResolverPorts(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "cmd/strace-go/text_renderer.go"))
	if err != nil {
		t.Fatalf("read text_renderer.go: %v", err)
	}
	text := string(source)
	for _, required := range []string{
		"type traceTimeFormatter interface",
		"type traceSymbolResolver interface",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("text renderer is missing narrow port %q", required)
		}
	}
	for _, forbidden := range []string{
		"timeFormatter *TimeFormatter",
		"resolver      *stacktrace.Resolver",
		"TimeFormatter *TimeFormatter",
		"Resolver      *stacktrace.Resolver",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("text renderer still depends on concrete owner %q", forbidden)
		}
	}
}

type fakeTextTimeFormatter struct {
	prefix string
	now    uint64
}

func (f fakeTextTimeFormatter) Prefix(uint64, traceTimePolicy) string {
	return f.prefix
}

func (f fakeTextTimeFormatter) NowMonoNs() uint64 {
	return f.now
}

type fakeTextSymbolResolver struct {
	values map[uint64]string
}

func (r fakeTextSymbolResolver) Resolve(ip uint64) string {
	return r.values[ip]
}

func TestTextRendererUsesInjectedTimeAndResolverPorts(t *testing.T) {
	var output strings.Builder
	opts := testOptions()
	opts.StackTrace = true
	renderer := newTextRenderer(TextRendererDeps{
		Out:           &output,
		Policy:        newTraceOutputPolicy(opts),
		TimeFormatter: fakeTextTimeFormatter{prefix: "TIME ", now: 17},
		StackTraces:   &fakeTraceStackTraceReader{ips: [127]uint64{0x1234}},
		Resolver:      fakeTextSymbolResolver{values: map[uint64]string{0x1234: "fake_symbol"}},
	})

	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0, stackID: 7},
		meta:           syscallMeta(syscallIDByName(t, "getpid")),
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	if !strings.Contains(output.String(), "TIME getpid()") || !strings.Contains(output.String(), " > fake_symbol\n") {
		t.Fatalf("renderer output = %q, want injected time and symbol", output.String())
	}
}
