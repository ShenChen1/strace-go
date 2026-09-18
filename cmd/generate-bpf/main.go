package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

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
	directory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve BPF source directory: %w", err)
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
		args := bpfArguments(target, *compiler, directory, collection.name, collection.source)
		if err := command("go", args...); err != nil {
			return fmt.Errorf("generate %s/%s: %w", target, collection.name, err)
		}
		if err := normalizeGeneratedBuildTag(target, directory, collection.name); err != nil {
			return fmt.Errorf("normalize %s/%s: %w", target, collection.name, err)
		}
	}
	return nil
}

// bpf2go emits the generic x86 userspace tag; this project only supports native amd64.
func normalizeGeneratedBuildTag(target architecture.Architecture, directory, collection string) error {
	if target != architecture.AMD64 {
		return nil
	}
	path := filepath.Join(directory, "cmd", "strace-go", strings.ToLower(collection)+"_x86_bpfel.go")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	const generatedTag = "//go:build (386 || amd64) && linux"
	const targetTag = "//go:build linux && amd64"
	if !bytes.Contains(data, []byte(generatedTag)) {
		return fmt.Errorf("generated build tag missing: %s", path)
	}
	updated := bytes.Replace(data, []byte(generatedTag), []byte(targetTag), 1)
	if err := os.WriteFile(path, updated, 0644); err != nil {
		return err
	}
	return nil
}

func command(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func bpfArguments(target architecture.Architecture, compiler, directory, name, source string) []string {
	return []string{"run", "github.com/cilium/ebpf/cmd/bpf2go", "-cc", compiler,
		"-go-package", "main", "-target", string(target), "-tags", "linux",
		"-output-dir", "cmd/strace-go", name, filepath.Join("bpf", source),
		"--", "-mcpu=v3", "-fdebug-prefix-map=" + directory + "=."}
}
