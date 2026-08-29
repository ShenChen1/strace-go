package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const killOnExitHelperEnv = "STRACE_GO_KILL_ON_EXIT_HELPER"

func TestKillOnExitTerminatesTraceCommand(t *testing.T) {
	if os.Getenv(killOnExitHelperEnv) != "" {
		startKillOnExitHelper(t)
		return
	}

	helper := exec.Command(os.Args[0], "-test.run=^TestKillOnExitTerminatesTraceCommand$")
	helper.Env = append(os.Environ(), killOnExitHelperEnv+"=1")
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatalf("create helper stdout pipe: %v", err)
	}
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read tracee pid: %v", scanner.Err())
	}
	traceePID, err := strconv.Atoi(scanner.Text())
	if err != nil || traceePID <= 0 {
		t.Fatalf("tracee pid = %q, error = %v", scanner.Text(), err)
	}
	defer unix.Kill(traceePID, unix.SIGKILL)
	if err := helper.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	waitForProcessExit(t, traceePID, 3*time.Second)
}

func startKillOnExitHelper(t *testing.T) {
	t.Helper()
	cmd := newTraceCommand(traceCommandSpec{
		args:       []string{"/bin/sleep", "30"},
		killOnExit: true,
	}, nil)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start trace command: %v", err)
	}
	fmt.Println(cmd.Process.Pid)
}

func waitForProcessExit(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("check tracee %d: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tracee %d survived its parent", pid)
}
