package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	defaultCaptureHeaderPath = "bpf/capture_manifest_generated.h"
	defaultCaptureGoPath     = "cmd/strace-go/bpf_capture_manifest_generated.go"
)

func main() {
	if err := runCaptureManifestGenerator(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCaptureManifestGenerator(args []string) error {
	flags := flag.NewFlagSet("generate-capture-manifest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	headerPath := flags.String("header", defaultCaptureHeaderPath, "generated C header path")
	goPath := flags.String("go", defaultCaptureGoPath, "generated Go source path")
	check := flags.Bool("check", false, "check generated files without writing them")
	if err := flags.Parse(args); err != nil {
		return err
	}
	root, err := findCaptureManifestRepoRoot()
	if err != nil {
		return err
	}
	manifest := newCaptureManifest()
	header, err := renderCaptureHeader(manifest)
	if err != nil {
		return fmt.Errorf("render C capture manifest: %w", err)
	}
	goSource, err := renderCaptureGo(manifest)
	if err != nil {
		return fmt.Errorf("render Go capture manifest: %w", err)
	}
	headerOutput := resolveCaptureManifestPath(root, *headerPath)
	goOutput := resolveCaptureManifestPath(root, *goPath)
	if *check {
		if err := checkCaptureManifestFile(headerOutput, header); err != nil {
			return err
		}
		return checkCaptureManifestFile(goOutput, goSource)
	}
	if err := writeCaptureManifestFile(headerOutput, header); err != nil {
		return err
	}
	if err := writeCaptureManifestFile(goOutput, goSource); err != nil {
		return err
	}
	return nil
}

func writeCaptureManifestFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func checkCaptureManifestFile(path, want string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read generated file %s: %w", path, err)
	}
	if string(data) != want {
		return fmt.Errorf("generated file is stale: %s", path)
	}
	return nil
}

func findCaptureManifestRepoRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if isCaptureManifestFile(filepath.Join(directory, "go.mod")) &&
			isCaptureManifestDirectory(filepath.Join(directory, "cmd", "generate-capture-manifest")) {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("repository root not found from %s", directory)
		}
		directory = parent
	}
}

func resolveCaptureManifestPath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func isCaptureManifestFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isCaptureManifestDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
