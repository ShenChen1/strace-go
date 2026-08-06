package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

const overrideAuditDetailHeader = "name\tstatus\treason\toverride_args\toverride_types\tbtf_args\tbtf_types"

type overrideAuditStatus string

const (
	overrideAuditRedundant         overrideAuditStatus = "redundant"
	overrideAuditMissingBTF        overrideAuditStatus = "missing_btf"
	overrideAuditNormalizedMatch   overrideAuditStatus = "normalized_match"
	overrideAuditSemanticOverride  overrideAuditStatus = "semantic_override"
	overrideAuditSignatureMismatch overrideAuditStatus = "signature_mismatch"
)

type overrideAuditRow struct {
	Name     string
	Status   overrideAuditStatus
	Reason   string
	Override SyscallMeta
	BTF      SyscallMeta
}

func writeOverrideAudit(stdout io.Writer, source btfSyscallSource, overrides map[string]SyscallMeta, aliases map[string]string) error {
	btf, err := source.LoadBTFSyscalls()
	if err != nil {
		return fmt.Errorf("load BTF syscalls: %w", err)
	}
	redundant := redundantManualOverrides(overrides, btf, aliases)
	for _, name := range redundant {
		if _, err := fmt.Fprintln(stdout, name); err != nil {
			return fmt.Errorf("write override audit: %w", err)
		}
	}
	return nil
}

func writeOverrideAuditDetail(stdout io.Writer, source btfSyscallSource, overrides map[string]SyscallMeta, aliases map[string]string) error {
	btf, diagnostics, err := loadOverrideAuditDataset(source)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, overrideAuditDetailHeader); err != nil {
		return fmt.Errorf("write override audit detail: %w", err)
	}
	for _, row := range overrideAuditRows(overrides, btf, aliases, diagnostics) {
		if _, err := fmt.Fprintln(stdout, formatOverrideAuditRow(row)); err != nil {
			return fmt.Errorf("write override audit detail: %w", err)
		}
	}
	return nil
}

func loadOverrideAuditDataset(source btfSyscallSource) (map[string]SyscallMeta, map[string]btfSyscallDiagnostic, error) {
	if datasetSource, ok := source.(btfSyscallDatasetSource); ok {
		dataset, err := datasetSource.LoadBTFSyscallDataset()
		if err != nil {
			return nil, nil, fmt.Errorf("load BTF syscall dataset: %w", err)
		}
		return dataset.Syscalls, dataset.Diagnostics, nil
	}

	btf, err := source.LoadBTFSyscalls()
	if err != nil {
		return nil, nil, fmt.Errorf("load BTF syscalls: %w", err)
	}
	diagnostics, err := loadOverrideAuditDiagnostics(source)
	if err != nil {
		return nil, nil, err
	}
	return btf, diagnostics, nil
}

func loadOverrideAuditDiagnostics(source btfSyscallSource) (map[string]btfSyscallDiagnostic, error) {
	diagnosticSource, ok := source.(btfSyscallDiagnosticsSource)
	if !ok {
		return nil, nil
	}
	diagnostics, err := diagnosticSource.LoadBTFSyscallDiagnostics()
	if err != nil {
		return nil, fmt.Errorf("load BTF syscall diagnostics: %w", err)
	}
	return diagnostics, nil
}

func redundantManualOverrides(overrides map[string]SyscallMeta, btf map[string]SyscallMeta, aliases map[string]string) []string {
	var redundant []string
	for name, override := range overrides {
		btfMeta, ok := auditBTFMeta(name, btf, aliases)
		if !ok {
			continue
		}
		if sameSignature(override, btfMeta) {
			redundant = append(redundant, name)
		}
	}
	sort.Strings(redundant)
	return redundant
}

func overrideAuditRows(overrides map[string]SyscallMeta, btf map[string]SyscallMeta, aliases map[string]string, diagnostics map[string]btfSyscallDiagnostic) []overrideAuditRow {
	rows := make([]overrideAuditRow, 0, len(overrides))
	for name, override := range overrides {
		btfMeta, ok := auditBTFMeta(name, btf, aliases)
		if !ok {
			rows = append(rows, overrideAuditRow{
				Name:     name,
				Status:   overrideAuditMissingBTF,
				Reason:   missingBTFReason(name, diagnostics, aliases),
				Override: override,
			})
			continue
		}
		status, reason := overrideAuditSignatureStatus(name, override, btfMeta)
		rows = append(rows, overrideAuditRow{
			Name:     name,
			Status:   status,
			Reason:   reason,
			Override: override,
			BTF:      btfMeta,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Name < rows[j].Name
	})
	return rows
}

func missingBTFReason(name string, diagnostics map[string]btfSyscallDiagnostic, aliases map[string]string) string {
	if diagnostic, ok := auditBTFDiagnostic(name, diagnostics, aliases); ok {
		return diagnostic.Reason
	}
	return "no_btf_metadata"
}

func auditBTFMeta(name string, btf map[string]SyscallMeta, aliases map[string]string) (SyscallMeta, bool) {
	if meta, ok := btf[name]; ok {
		return meta, true
	}
	for btfName, syscallentName := range aliases {
		if syscallentName != name {
			continue
		}
		meta, ok := btf[btfName]
		return meta, ok
	}
	return SyscallMeta{}, false
}

func auditBTFDiagnostic(name string, diagnostics map[string]btfSyscallDiagnostic, aliases map[string]string) (btfSyscallDiagnostic, bool) {
	if diagnostic, ok := diagnostics[name]; ok {
		return diagnostic, true
	}
	for btfName, syscallentName := range aliases {
		if syscallentName != name {
			continue
		}
		diagnostic, ok := diagnostics[btfName]
		return diagnostic, ok
	}
	return btfSyscallDiagnostic{}, false
}

func overrideAuditSignatureStatus(name string, override SyscallMeta, btfMeta SyscallMeta) (overrideAuditStatus, string) {
	if sameSignature(override, btfMeta) {
		return overrideAuditRedundant, "exact_signature"
	}
	if sameNormalizedSignature(override, btfMeta) {
		return overrideAuditNormalizedMatch, normalizedMismatchReason(override, btfMeta)
	}
	if reason, ok := semanticOverrideReason(name, override, btfMeta); ok {
		return overrideAuditSemanticOverride, reason
	}
	var reasons []string
	if !sameStringSlice(override.Args, btfMeta.Args) {
		reasons = append(reasons, "args")
	}
	if !sameStringSlice(override.ArgTypes, btfMeta.ArgTypes) {
		reasons = append(reasons, "arg_types")
	}
	return overrideAuditSignatureMismatch, strings.Join(reasons, ",")
}

func semanticOverrideReason(name string, override SyscallMeta, btfMeta SyscallMeta) (string, bool) {
	spec, ok := semanticOverrideSpecs[name]
	if !ok {
		return "", false
	}
	if !sameStringSlice(override.Args, spec.OverrideArgs) ||
		!sameStringSlice(override.ArgTypes, spec.OverrideType) ||
		!sameStringSlice(btfMeta.Args, spec.BTFArgs) ||
		!sameStringSlice(btfMeta.ArgTypes, spec.BTFType) {
		return "", false
	}
	return spec.Reason, true
}

func sameNormalizedSignature(a SyscallMeta, b SyscallMeta) bool {
	return sameNormalizedStringSlice(a.Args, b.Args, normalizeAuditArgName) &&
		sameNormalizedStringSlice(a.ArgTypes, b.ArgTypes, normalizeAuditType)
}

func sameNormalizedStringSlice(a []string, b []string, normalize func(string) string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalize(a[i]) != normalize(b[i]) {
			return false
		}
	}
	return true
}

func normalizedMismatchReason(override SyscallMeta, btfMeta SyscallMeta) string {
	var reasons []string
	if !sameStringSlice(override.Args, btfMeta.Args) {
		reasons = append(reasons, "normalized_args")
	}
	if !sameStringSlice(override.ArgTypes, btfMeta.ArgTypes) {
		reasons = append(reasons, "normalized_arg_types")
	}
	return strings.Join(reasons, ",")
}

func normalizeAuditArgName(name string) string {
	return strings.TrimLeft(name, "_")
}

func normalizeAuditType(typ string) string {
	switch typ {
	case "long unsigned int":
		return "unsigned long"
	case "long int":
		return "long"
	default:
		return typ
	}
}

func formatOverrideAuditRow(row overrideAuditRow) string {
	fields := []string{
		row.Name,
		string(row.Status),
		row.Reason,
		joinAuditValues(row.Override.Args),
		joinAuditValues(row.Override.ArgTypes),
		joinAuditValues(row.BTF.Args),
		joinAuditValues(row.BTF.ArgTypes),
	}
	return strings.Join(fields, "\t")
}

func joinAuditValues(values []string) string {
	normalized := make([]string, len(values))
	for i, value := range values {
		normalized[i] = normalizeAuditValue(value)
	}
	return strings.Join(normalized, ",")
}

func normalizeAuditValue(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func sameSignature(a SyscallMeta, b SyscallMeta) bool {
	return sameStringSlice(a.Args, b.Args) && sameStringSlice(a.ArgTypes, b.ArgTypes)
}

func sameStringSlice(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
