package main

import (
	"bytes"
	"errors"
	"testing"

	"strace-go/pkg/cli"
)

func TestRenderTraceTipZeroMatchesUpstreamCompactOutput(t *testing.T) {
	var output bytes.Buffer
	renderTraceTip(&output, cli.TipsModeCompact, 0)
	want := "" +
		"  ______________________________________________         ____\n" +
		" /                                              \\       /    \\\n" +
		" | strace has an extensive manual page          |      |-. .-.|\n" +
		" | that covers all the possible options         \\      (_@)(_@)\n" +
		" | and contains several useful invocation        \\     .---_  \\\n" +
		" | examples.                                     _\\   /..   \\_/\n" +
		" |                                              /     |__.-^ /\n" +
		" |                                              |         }  |\n" +
		" \\______________________________________________/        |   [\n" +
		"                                                         [  ]\n"
	if output.String() != want {
		t.Fatalf("compact tip output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRenderTraceTipNoneWritesNothing(t *testing.T) {
	var output bytes.Buffer
	renderTraceTip(&output, cli.TipsModeNone, 0)
	if output.Len() != 0 {
		t.Fatalf("tips=none output = %q", output.String())
	}
}

type failingTipsWriter struct {
	err error
}

func (w failingTipsWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRenderTraceTipReportsWriteFailure(t *testing.T) {
	want := errors.New("tip output failed")
	if err := renderTraceTip(failingTipsWriter{err: want}, cli.TipsModeCompact, 0); !errors.Is(err, want) {
		t.Fatalf("renderTraceTip() error = %v, want %v", err, want)
	}
}
