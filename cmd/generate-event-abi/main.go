package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	defaultHeaderPath = "bpf/event_abi_generated.h"
	defaultGoPath     = "cmd/strace-go/event_abi_generated.go"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("generate-event-abi", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	headerPath := flags.String("header", defaultHeaderPath, "generated C header path")
	goPath := flags.String("go", defaultGoPath, "generated Go constants path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	root, err := findRepoRoot()
	if err != nil {
		return err
	}
	headerOutput := resolveOutputPath(root, *headerPath)
	goOutput := resolveOutputPath(root, *goPath)
	if err := writeProtocolHeader(headerOutput); err != nil {
		return fmt.Errorf("write C protocol header: %w", err)
	}
	if err := writeProtocolGo(goOutput); err != nil {
		return fmt.Errorf("write Go protocol constants: %w", err)
	}
	return nil
}

func findRepoRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("repository root with go.mod not found from %s", directory)
		}
		directory = parent
	}
}

func resolveOutputPath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}
