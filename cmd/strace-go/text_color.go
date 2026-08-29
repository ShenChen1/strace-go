package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"strace-go/pkg/cli"
)

const traceColorReset = "\x1b[0m"

type traceColorPalette struct {
	syscall string
	argval  string
	punct   string
}

type traceColorEnvironment struct {
	lookupEnv func(string) (string, bool)
	isTTY     func(io.Writer) bool
}

type traceColorWriter struct {
	out     io.Writer
	palette traceColorPalette
}

func newTraceColorWriter(out io.Writer, palette traceColorPalette) *traceColorWriter {
	return &traceColorWriter{out: out, palette: palette}
}

func (w *traceColorWriter) Write(input []byte) (int, error) {
	if w == nil || w.out == nil {
		return 0, fmt.Errorf("color output writer is unavailable")
	}
	colored := colorizeTraceText(input, w.palette)
	written, err := w.out.Write(colored)
	if err == nil && written != len(colored) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(input), nil
}

func parseTraceColorPalette(spec string) traceColorPalette {
	palette := traceColorPalette{
		syscall: traceSGR("33"),
		argval:  traceSGR("35"),
		punct:   traceColorReset,
	}
	for _, item := range strings.Split(spec, ":") {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !validTraceSGR(value) {
			continue
		}
		sequence := traceSGR(value)
		switch key {
		case "syscall":
			palette.syscall = sequence
		case "argval":
			palette.argval = sequence
		case "punct":
			palette.punct = sequence
		}
	}
	return palette
}

func validTraceSGR(value string) bool {
	hasDigit := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' {
			hasDigit = true
			continue
		}
		if character != ';' {
			return false
		}
	}
	return hasDigit
}

func traceSGR(value string) string {
	return "\x1b[" + value + "m"
}

func colorizeTraceText(input []byte, palette traceColorPalette) []byte {
	var output strings.Builder
	output.Grow(len(input))
	remaining := string(input)
	for len(remaining) > 0 {
		lineEnd := strings.IndexByte(remaining, '\n')
		if lineEnd < 0 {
			colorizeTraceLine(&output, remaining, palette)
			break
		}
		colorizeTraceLine(&output, remaining[:lineEnd], palette)
		output.WriteByte('\n')
		remaining = remaining[lineEnd+1:]
	}
	return []byte(output.String())
}

func colorizeTraceLine(output *strings.Builder, line string, palette traceColorPalette) {
	open := strings.IndexByte(line, '(')
	if open < 1 {
		output.WriteString(line)
		return
	}
	nameStart := open
	for nameStart > 0 && isSyscallNameByte(line[nameStart-1]) {
		nameStart--
	}
	if nameStart == open {
		output.WriteString(line)
		return
	}
	output.WriteString(line[:nameStart])
	writeTraceColorSpan(output, palette.syscall, line[nameStart:open])
	colorizeTraceArguments(output, line[open:], palette)
}

func colorizeTraceArguments(output *strings.Builder, text string, palette traceColorPalette) {
	for index := 0; index < len(text); {
		if text[index] == '"' {
			end := quotedTraceValueEnd(text, index)
			writeTraceColorSpan(output, palette.argval, text[index:end])
			index = end
			continue
		}
		if strings.ContainsRune("()[]{},", rune(text[index])) {
			writeTraceColorSpan(output, palette.punct, text[index:index+1])
			index++
			continue
		}
		output.WriteByte(text[index])
		index++
	}
}

func quotedTraceValueEnd(text string, start int) int {
	escaped := false
	for index := start + 1; index < len(text); index++ {
		if text[index] == '"' && !escaped {
			return index + 1
		}
		if text[index] == '\\' {
			escaped = !escaped
		} else {
			escaped = false
		}
	}
	return len(text)
}

func writeTraceColorSpan(output *strings.Builder, sequence, text string) {
	output.WriteString(sequence)
	output.WriteString(text)
	output.WriteString(traceColorReset)
}

func isSyscallNameByte(value byte) bool {
	return value == '_' || value == '?' || value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func enableTraceColor(output *TraceOutput, mode string, textOutput bool) {
	if output == nil || !traceColorEnabled(mode, textOutput, output.writer, systemTraceColorEnvironment()) {
		return
	}
	spec, _ := os.LookupEnv("STRACE_COLORS")
	output.writer = newTraceColorWriter(output.writer, parseTraceColorPalette(spec))
}

func traceColorEnabled(mode string, textOutput bool, writer io.Writer, environment traceColorEnvironment) bool {
	if !textOutput || mode == cli.ColorModeNever {
		return false
	}
	if mode == cli.ColorModeAlways {
		return true
	}
	if environment.lookupEnv == nil || environment.isTTY == nil || !environment.isTTY(writer) {
		return false
	}
	if _, set := environment.lookupEnv("NO_COLOR"); set {
		return false
	}
	term, set := environment.lookupEnv("TERM")
	return set && term != "" && !strings.EqualFold(term, "dumb") && !strings.EqualFold(term, "unknown")
}

func systemTraceColorEnvironment() traceColorEnvironment {
	return traceColorEnvironment{lookupEnv: os.LookupEnv, isTTY: isTerminalWriter}
}

func isTerminalWriter(writer io.Writer) bool {
	fdWriter, ok := writer.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(fdWriter.Fd()), unix.TCGETS)
	return err == nil
}
