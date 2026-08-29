package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

type separateTracePIDFile struct {
	path   string
	file   *os.File
	writer *bufio.Writer
}

type separateTraceOutputWriter struct {
	basePath string
	flags    int
	selected int
	files    map[int]*separateTracePIDFile
	closed   bool
}

func newSeparateTraceOutputWriter(basePath string, appendMode bool) *separateTraceOutputWriter {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	return &separateTraceOutputWriter{basePath: basePath, flags: flags}
}

func (w *separateTraceOutputWriter) SelectPID(pid int) error {
	if w == nil || w.closed {
		return fmt.Errorf("separate trace output is unavailable")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid trace output pid %d", pid)
	}
	w.selected = pid
	return nil
}

func (w *separateTraceOutputWriter) Write(data []byte) (int, error) {
	if w == nil || w.closed {
		return 0, fmt.Errorf("separate trace output is unavailable")
	}
	if w.selected <= 0 {
		return 0, fmt.Errorf("trace output pid is not selected")
	}
	output, err := w.fileForPID(w.selected)
	if err != nil {
		return 0, err
	}
	n, err := output.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *separateTraceOutputWriter) fileForPID(pid int) (*separateTracePIDFile, error) {
	if output := w.files[pid]; output != nil {
		return output, nil
	}
	path := w.basePath + "." + strconv.Itoa(pid)
	file, err := os.OpenFile(path, w.flags, 0666)
	if err != nil {
		return nil, fmt.Errorf("create separate output file %s: %w", path, err)
	}
	if w.files == nil {
		w.files = make(map[int]*separateTracePIDFile)
	}
	output := &separateTracePIDFile{
		path:   path,
		file:   file,
		writer: bufio.NewWriterSize(file, traceOutputBufferSize),
	}
	w.files[pid] = output
	return output, nil
}

func (w *separateTraceOutputWriter) Flush() error {
	if w == nil || w.closed {
		return nil
	}
	var flushErr error
	for _, output := range w.files {
		if err := output.writer.Flush(); err != nil {
			flushErr = errors.Join(flushErr, fmt.Errorf("flush separate output file %s: %w", output.path, err))
		}
	}
	return flushErr
}

func (w *separateTraceOutputWriter) Close() error {
	if w == nil || w.closed {
		return nil
	}
	flushErr := w.Flush()
	w.closed = true
	closeErr := flushErr
	for _, output := range w.files {
		if err := output.file.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close separate output file %s: %w", output.path, err))
		}
	}
	return closeErr
}
