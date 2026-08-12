package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// IMPACT: setupOutput prepares the owned output resource for saving strace text traces.
func setupOutput(outFileOpt string, appendMode bool) (*TraceOutput, error) {
	if outFileOpt == "" {
		return newTraceOutput(TraceOutputDeps{Writer: os.Stderr})
	}
	if strings.HasPrefix(outFileOpt, "|") || strings.HasPrefix(outFileOpt, "!") {
		cmdStr := outFileOpt[1:]
		cmd := exec.Command("sh", "-c", cmdStr)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("create output pipe: %w", err)
		}
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("start output command: %w", err)
		}
		output, err := newTraceOutput(TraceOutputDeps{
			Writer:  stdin,
			Closer:  stdin,
			Command: execTraceOutputWaiter{command: cmd},
		})
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return nil, err
		}
		return output, nil
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	outFile, err := os.OpenFile(outFileOpt, flags, 0666)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	output, err := newTraceOutput(TraceOutputDeps{Writer: outFile, Closer: outFile})
	if err != nil {
		_ = outFile.Close()
		return nil, err
	}
	return output, nil
}
