package main

import (
	"errors"
	"os"
	"strings"
)

// traceOutputPathError preserves the output errno while exposing the path the
// user configured instead of internal per-PID routing details.
type traceOutputPathError struct {
	path  string
	cause error
}

func newTraceOutputPathError(path string, err error) *traceOutputPathError {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return &traceOutputPathError{path: path, cause: err}
}

func (e *traceOutputPathError) Error() string {
	if e == nil {
		return ""
	}
	return e.path + ": " + capitalizedDiagnosticError(e.cause)
}

func (e *traceOutputPathError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func capitalizedDiagnosticError(err error) string {
	if err == nil {
		return "Unknown error"
	}
	message := err.Error()
	if message == "" {
		return "Unknown error"
	}
	return strings.ToUpper(message[:1]) + message[1:]
}
