package main

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

type traceUnknownChildEffect interface {
	HandleUnknownChild(action uint32, pid int, quiet bool)
}

type traceUnknownChildWait func(pid int) error

type traceUnknownChildDiagnosticDeps struct {
	Output      io.Writer
	ProgramName string
	Reap        bool
	Wait        traceUnknownChildWait
}

type traceUnknownChildDiagnostics struct {
	output      io.Writer
	programName string
	reap        bool
	wait        traceUnknownChildWait
}

func newTraceUnknownChildDiagnostics(deps traceUnknownChildDiagnosticDeps) *traceUnknownChildDiagnostics {
	return &traceUnknownChildDiagnostics{
		output:      deps.Output,
		programName: deps.ProgramName,
		reap:        deps.Reap,
		wait:        deps.Wait,
	}
}

func (d *traceUnknownChildDiagnostics) HandleUnknownChild(action uint32, pid int, quiet bool) {
	if d == nil || d.output == nil || pid <= 0 {
		return
	}
	if action == lifecycleUnknownExit && d.reap {
		if d.wait == nil {
			fmt.Fprintf(d.output, "%s: Cannot reap unknown pid %d: waiter unavailable\n", d.name(), pid)
			return
		}
		if err := d.wait(pid); err != nil {
			fmt.Fprintf(d.output, "%s: Cannot reap unknown pid %d: %v\n", d.name(), pid, err)
			return
		}
	}
	if quiet {
		return
	}
	switch action {
	case lifecycleUnknownDetach:
		fmt.Fprintf(d.output, "%s: Detached unknown pid %d\n", d.name(), pid)
	case lifecycleUnknownExit:
		fmt.Fprintf(d.output, "%s: Exit of unknown pid %d ignored\n", d.name(), pid)
	}
}

func (d *traceUnknownChildDiagnostics) name() string {
	if d.programName == "" {
		return "strace"
	}
	return d.programName
}

func waitUnknownChild(pid int) error {
	for {
		var status unix.WaitStatus
		waited, err := unix.Wait4(pid, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if waited != pid {
			return fmt.Errorf("waited for pid %d", waited)
		}
		return nil
	}
}

var _ traceUnknownChildEffect = (*traceUnknownChildDiagnostics)(nil)
