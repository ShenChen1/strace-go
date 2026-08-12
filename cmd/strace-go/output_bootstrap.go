package main

import (
	"errors"
	"fmt"
	"io"
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
			return nil, fmt.Errorf("start output command: %w", errors.Join(err, cleanupOutputBootstrap(stdin, nil)))
		}
		output, err := newTraceOutput(TraceOutputDeps{
			Writer:  stdin,
			Closer:  stdin,
			Command: execTraceOutputWaiter{command: cmd},
		})
		if err != nil {
			return nil, fmt.Errorf("create output pipe: %w", errors.Join(err, cleanupOutputBootstrap(stdin, execTraceOutputWaiter{command: cmd})))
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
		return nil, fmt.Errorf("create output file: %w", errors.Join(err, closeOutputFile(outFileOpt, outFile)))
	}
	return output, nil
}

func cleanupOutputBootstrap(writer io.Closer, command traceOutputWaiter) error {
	var cleanupErr error
	if writer != nil {
		cleanupErr = errors.Join(cleanupErr, writer.Close())
	}
	if command != nil {
		cleanupErr = errors.Join(cleanupErr, command.Wait())
	}
	return cleanupErr
}

func closeOutputFile(path string, file *os.File) error {
	if file == nil {
		return nil
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output file %s: %w", path, err)
	}
	return nil
}
