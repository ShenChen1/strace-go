package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

type SyscallMeta struct {
	Name     string
	Args     []string
	ArgTypes []string
	Flags    string
}

type syscallMapLoader interface {
	Load() (map[int]SyscallMeta, error)
}

type syscallTableWriter interface {
	Write(path string, syscalls map[int]SyscallMeta) error
}

type generatorCommand struct {
	loader            syscallMapLoader
	resolutionLoader  syscallMetadataResolutionLoader
	writer            syscallTableWriter
	auditSource       btfSyscallSource
	tracepointSource  tracepointSyscallSource
	overrides         map[string]SyscallMeta
	aliases           map[string]string
	defaultOutputPath string
}

func main() {
	if err := runGenerateSyscalls(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func runGenerateSyscalls(args []string, stdout io.Writer) error {
	return newGeneratorCommand().Run(args, stdout)
}

func newGeneratorCommand() generatorCommand {
	return generatorCommand{
		loader:           defaultSyscallMetadataLoader{},
		resolutionLoader: defaultSyscallMetadataLoader{},
		writer:           goSyscallTableWriter{},
		auditSource:      kernelBTFSource{},
		tracepointSource: kernelTracepointFormatSource{},
		overrides:        allSyscallOverrides(),
		aliases:          btfNameToSyscallent,
	}
}

func (c generatorCommand) Run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("generate-syscalls", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	auditOverrides := flags.Bool("audit-overrides", false, "print manual overrides already covered by BTF")
	auditOverrideDetails := flags.Bool("audit-overrides-detail", false, "print detailed manual override audit rows")
	auditTracepointOverrides := flags.Bool("audit-tracepoint-overrides", false, "print manual override coverage from syscall tracepoint formats")
	auditResolution := flags.Bool("audit-resolution", false, "print final syscall metadata resolution provenance")
	outputPath := flags.String("output", c.defaultOutputPath, "generated syscall table output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *auditOverrideDetails {
		return writeOverrideAuditDetail(stdout, c.auditSource, c.overrides, c.aliases)
	}
	if *auditOverrides {
		return writeOverrideAudit(stdout, c.auditSource, c.overrides, c.aliases)
	}
	if *auditTracepointOverrides {
		return writeTracepointOverrideAudit(stdout, c.tracepointSource, c.overrides, c.aliases)
	}
	if *auditResolution {
		return writeResolutionAudit(stdout, c.resolutionLoader)
	}

	syscalls, err := c.loader.Load()
	if err != nil {
		return fmt.Errorf("load syscalls: %w", err)
	}

	resolvedOutputPath, err := c.outputPath(*outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	writer := c.syscallTableWriter()
	if err := writer.Write(resolvedOutputPath, syscalls); err != nil {
		return fmt.Errorf("write syscall table: %w", err)
	}
	return nil
}

func (c generatorCommand) outputPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	return resolveRepoPath(defaultSyscallTableRelPath)
}

func (c generatorCommand) syscallTableWriter() syscallTableWriter {
	if c.writer != nil {
		return c.writer
	}
	return goSyscallTableWriter{}
}
