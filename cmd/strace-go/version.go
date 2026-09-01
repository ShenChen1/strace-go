package main

import (
	"bytes"
	"fmt"
	"io"
)

const (
	straceOptionalFeatures = "no-m32-mpers no-mx32-mpers"
	versionStraussOffset   = 5
)

func renderVersion(out io.Writer, verbosity int) error {
	if out == nil {
		return fmt.Errorf("version output is nil")
	}
	var rendered bytes.Buffer
	fmt.Fprintf(&rendered, "strace -- version %s\n", straceVersion)
	fmt.Fprintf(&rendered, "Copyright (c) 1991-%s The strace developers <https://strace.io>.\n", straceCopyrightYear)
	fmt.Fprintln(&rendered, "This is free software; see the source for copying conditions.  There is NO")
	fmt.Fprintln(&rendered, "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.")
	fmt.Fprintf(&rendered, "\nOptional features enabled: %s\n", straceOptionalFeatures)

	lineCount := min(max(verbosity-versionStraussOffset, 0), len(traceTipStrauss))
	for _, line := range traceTipStrauss[:lineCount] {
		fmt.Fprintln(&rendered, line)
	}
	_, err := out.Write(rendered.Bytes())
	return err
}
