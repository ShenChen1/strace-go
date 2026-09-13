package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"strace-go/internal/architecture"
)

var collections = []struct{ name, source string }{
	{"bpf", "strace.c"},
	{"bpfEnterGeneric", "handlers_enter_generic.c"},
	{"bpfEnterPayload", "handlers_enter_payload.c"},
	{"bpfEnterPath", "handlers_enter_path.c"},
	{"bpfEnterMemory", "handlers_enter_memory.c"},
	{"bpfEnterControl", "handlers_enter_control.c"},
	{"bpfEnterStructured", "handlers_enter_structured.c"},
	{"bpfExit", "handlers_exit.c"},
	{"bpfRecvmsg", "handlers_recvmsg.c"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	requested := flag.String("arch", "", "target architecture: amd64 or arm64")
	environment := flag.String("goarch", os.Getenv("GOARCH"), "GOARCH requested by caller")
	compiler := flag.String("cc", "clang", "BPF-capable clang executable")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	target, err := architecture.Select(*requested, *environment, runtime.GOARCH)
	if err != nil {
		return err
	}
	fmt.Printf("Target architecture: %s\nLinux architecture: %s\nBPF target: bpfel\nSyscall metadata: linux/%s\n", target, target.LinuxName(), target)
	for _, generator := range []string{"generate-capture-manifest", "generate-event-abi"} {
		if err := command("go", "run", "./cmd/"+generator); err != nil {
			return err
		}
	}
	if err := command("go", "run", "./cmd/generate-syscalls", "-arch", string(target)); err != nil {
		return err
	}
	for _, collection := range collections {
		args := []string{"run", "github.com/cilium/ebpf/cmd/bpf2go", "-cc", *compiler,
			"-go-package", "main", "-target", string(target), "-tags", "linux",
			"-output-dir", "cmd/strace-go", collection.name, filepath.Join("bpf", collection.source), "--", "-mcpu=v3", "-fdebug-prefix-map=" + mustWorkingDirectory() + "=."}
		if err := command("go", args...); err != nil {
			return fmt.Errorf("generate %s/%s: %w", target, collection.name, err)
		}
	}
	return nil
}

func command(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func mustWorkingDirectory() string {
	directory, err := os.Getwd()
	if err != nil {
		return "."
	}
	return directory
}
