package main

import (
	"fmt"
	"io"
	"sort"
)

const tracepointAuditDetailHeader = "name\tstatus\treason\toverride_args\toverride_types\ttracepoint_args\ttracepoint_types"

func writeTracepointOverrideAudit(stdout io.Writer, source tracepointSyscallSource, overrides map[string]SyscallMeta, aliases map[string]string) error {
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	metadata, err := source.LoadTracepointSyscalls(tracepointLookupNames(names, aliases))
	if err != nil {
		return fmt.Errorf("load syscall tracepoint metadata: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, tracepointAuditDetailHeader); err != nil {
		return fmt.Errorf("write tracepoint audit header: %w", err)
	}
	for _, name := range names {
		tracepoint, _ := tracepointAuditMeta(name, metadata, aliases)
		row := formatTracepointAuditRow(name, overrides[name], tracepoint)
		if _, err := fmt.Fprintln(stdout, row); err != nil {
			return fmt.Errorf("write tracepoint audit row: %w", err)
		}
	}
	return nil
}

func tracepointAuditMeta(name string, metadata map[string]SyscallMeta, aliases map[string]string) (SyscallMeta, bool) {
	if meta, ok := metadata[name]; ok {
		return meta, true
	}
	for _, tracepointName := range tracepointAliasNames(name, aliases) {
		meta, ok := metadata[tracepointName]
		if ok {
			return meta, true
		}
	}
	return SyscallMeta{}, false
}

func formatTracepointAuditRow(name string, override, tracepoint SyscallMeta) string {
	status := overrideAuditMissingBTF
	reason := "no_tracepoint_metadata"
	if len(tracepoint.Args) > 0 || len(tracepoint.ArgTypes) > 0 || tracepoint.Name != "" {
		status, reason = overrideAuditSignatureStatus(name, override, tracepoint)
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s",
		name,
		status,
		reason,
		joinAuditValues(override.Args),
		joinAuditValues(override.ArgTypes),
		joinAuditValues(tracepoint.Args),
		joinAuditValues(tracepoint.ArgTypes),
	)
}
