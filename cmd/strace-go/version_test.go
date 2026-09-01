package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRenderVersionBaseOutput(t *testing.T) {
	var output bytes.Buffer
	if err := renderVersion(&output, 1); err != nil {
		t.Fatalf("renderVersion: %v", err)
	}
	want := fmt.Sprintf(
		"strace -- version %s\n"+
			"Copyright (c) 1991-%s The strace developers <https://strace.io>.\n"+
			"This is free software; see the source for copying conditions.  There is NO\n"+
			"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"+
			"Optional features enabled: no-m32-mpers no-mx32-mpers\n",
		straceVersion,
		straceCopyrightYear,
	)
	if output.String() != want {
		t.Fatalf("version output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRenderVersionVerbosityAppendsStrauss(t *testing.T) {
	var output bytes.Buffer
	if err := renderVersion(&output, 16); err != nil {
		t.Fatalf("renderVersion: %v", err)
	}
	wantTail := "\n     ____\n" +
		"    /    \\\n" +
		"   |-. .-.|\n" +
		"   (_@)(_@)\n" +
		"   .---_  \\\n" +
		"  /..   \\_/\n" +
		"  |__.-^ /\n" +
		"      }  |\n" +
		"     |   [\n" +
		"     [  ]\n"
	if !strings.HasSuffix(output.String(), wantTail) {
		t.Fatalf("verbosity 16 tail:\n%s\nwant suffix:\n%s", output.String(), wantTail)
	}
}

func TestRenderVersionReportsWriteFailure(t *testing.T) {
	want := errors.New("version output failed")
	if err := renderVersion(failingTipsWriter{err: want}, 1); !errors.Is(err, want) {
		t.Fatalf("renderVersion error = %v, want %v", err, want)
	}
}
