package main

import (
	"bytes"
	"io"
	"testing"
)

func TestTraceColorWriterColorsSemanticTokens(t *testing.T) {
	var output bytes.Buffer
	writer := newTraceColorWriter(&output, parseTraceColorPalette("syscall=1;31:argval=1;32:punct=1;34"))
	input := []byte(`chdir("sample") = 0` + "\n")

	if _, err := writer.Write(input); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	want := "\x1b[1;31mchdir\x1b[0m\x1b[1;34m(\x1b[0m\x1b[1;32m\"sample\"\x1b[0m\x1b[1;34m)\x1b[0m = 0\n"
	if output.String() != want {
		t.Fatalf("colored output = %q, want %q", output.String(), want)
	}
}

func TestTraceColorAutoPolicyHonorsTerminalEnvironment(t *testing.T) {
	environment := traceColorEnvironment{
		lookupEnv: func(key string) (string, bool) {
			values := map[string]string{"TERM": "linux"}
			value, ok := values[key]
			return value, ok
		},
		isTTY: func(io.Writer) bool { return true },
	}
	if !traceColorEnabled("auto", true, &bytes.Buffer{}, environment) {
		t.Fatal("auto color disabled for a color terminal")
	}

	environment.lookupEnv = func(key string) (string, bool) {
		values := map[string]string{"TERM": "linux", "NO_COLOR": ""}
		value, ok := values[key]
		return value, ok
	}
	if traceColorEnabled("auto", true, &bytes.Buffer{}, environment) {
		t.Fatal("auto color ignored NO_COLOR")
	}
}

func TestTraceColorPaletteIgnoresInvalidSGR(t *testing.T) {
	palette := parseTraceColorPalette("syscall=1;31;bad:argval=１２:punct=1;34")

	if palette.syscall != traceSGR("33") || palette.argval != traceSGR("35") {
		t.Fatalf("invalid palette changed defaults: %+v", palette)
	}
	if palette.punct != traceSGR("1;34") {
		t.Fatalf("valid punctuation color = %q, want 1;34", palette.punct)
	}
}
