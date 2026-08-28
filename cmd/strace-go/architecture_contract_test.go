package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

// These assertions keep the catalog tied to real compile-time contracts.
var (
	_ traceStateOwner        = (*TraceState)(nil)
	_ traceFDStateOwner      = (*FDStateStore)(nil)
	_ traceEventPolicyOwner  = (*cliTraceEventPolicy)(nil)
	_ traceOutputPolicyOwner = (*cliTraceOutputPolicy)(nil)
	_ traceSummaryOwner      = (*SummaryStats)(nil)
	_ traceRecordDecoder     = (*traceRingbufRecordDecoder)(nil)
	_ traceEventSink         = (*TraceEventRouter)(nil)
	_ traceFinalizerOutput   = (*TraceOutput)(nil)
	_ handler.RegistryPort   = (*handler.Registry)(nil)
	_ meta.CatalogPort       = (*meta.Catalog)(nil)
)

type architecturePortContract struct {
	name              string
	portFile          string
	portType          string
	ownerFile         string
	ownerType         string
	ownerAssertion    string
	compositionFile   string
	compositionTokens []string
}

var traceArchitecturePortContracts = [...]architecturePortContract{
	{
		name:              "session state",
		portFile:          "cmd/strace-go/state_owner_port.go",
		portType:          "traceStateOwner",
		ownerFile:         "cmd/strace-go/event_state.go",
		ownerType:         "TraceState",
		ownerAssertion:    "var _ traceStateOwner = (*TraceState)(nil)",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"State         traceStateOwner"},
	},
	{
		name:              "FD state",
		portFile:          "cmd/strace-go/fd_state_owner_port.go",
		portType:          "traceFDStateOwner",
		ownerFile:         "cmd/strace-go/fd_state_store.go",
		ownerType:         "FDStateStore",
		ownerAssertion:    "var _ traceFDStateOwner = (*FDStateStore)(nil)",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"FDState       traceFDStateOwner"},
	},
	{
		name:              "event policy",
		portFile:          "cmd/strace-go/event_policy_owner_port.go",
		portType:          "traceEventPolicyOwner",
		ownerFile:         "cmd/strace-go/event_policy.go",
		ownerType:         "cliTraceEventPolicy",
		ownerAssertion:    "var _ traceEventPolicyOwner = (*cliTraceEventPolicy)(nil)",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"EventPolicy   traceEventPolicyOwner"},
	},
	{
		name:              "output policy",
		portFile:          "cmd/strace-go/output_policy_owner_port.go",
		portType:          "traceOutputPolicyOwner",
		ownerFile:         "cmd/strace-go/output_policy.go",
		ownerType:         "cliTraceOutputPolicy",
		ownerAssertion:    "var _ traceOutputPolicyOwner = (*cliTraceOutputPolicy)(nil)",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"OutputPolicy  traceOutputPolicyOwner"},
	},
	{
		name:              "summary state",
		portFile:          "cmd/strace-go/summary_stats.go",
		portType:          "traceSummaryOwner",
		ownerFile:         "cmd/strace-go/summary_stats.go",
		ownerType:         "SummaryStats",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"Summary       traceSummaryOwner"},
	},
	{
		name:              "record decoder",
		portFile:          "cmd/strace-go/trace_record_decoder.go",
		portType:          "traceRecordDecoder",
		ownerFile:         "cmd/strace-go/trace_record_decoder.go",
		ownerType:         "traceRingbufRecordDecoder",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"recordDecoder      traceRecordDecoder"},
	},
	{
		name:              "event sink",
		portFile:          "cmd/strace-go/event_reader.go",
		portType:          "traceEventSink",
		ownerFile:         "cmd/strace-go/event_router.go",
		ownerType:         "TraceEventRouter",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"var eventSink traceEventSink = router"},
	},
	{
		name:              "finalizer output",
		portFile:          "cmd/strace-go/run_finalizer.go",
		portType:          "traceFinalizerOutput",
		ownerFile:         "cmd/strace-go/trace_output.go",
		ownerType:         "TraceOutput",
		compositionFile:   "cmd/strace-go/session_composition.go",
		compositionTokens: []string{"Output        traceFinalizerOutput"},
	},
}

type architectureStateOwnerContract struct {
	name      string
	file      string
	typeName  string
	required  []string
	forbidden []string
}

var architectureOwnerForbiddenTokens = []string{
	"MemoryReader",
	"Ptrace",
	"ProcessVMReadv",
	"process_vm",
	"/proc/",
}

var traceArchitectureStateOwnerContracts = [...]architectureStateOwnerContract{
	{
		name:      "syscall correlation",
		file:      "cmd/strace-go/event_syscall_correlation.go",
		typeName:  "traceSyscallCorrelationState",
		required:  []string{"pendingSyscalls", "pendingExits", "pendingExecArgs", "suspendedSyscalls", "reusablePayload"},
		forbidden: architectureOwnerForbiddenTokens,
	},
	{
		name:      "unfinished output",
		file:      "cmd/strace-go/event_unfinished_state.go",
		typeName:  "traceUnfinishedState",
		required:  []string{"enabled", "unqueued", "inFlight", "reusable"},
		forbidden: architectureOwnerForbiddenTokens,
	},
	{
		name:      "task lifecycle",
		file:      "cmd/strace-go/event_task_lifecycle.go",
		typeName:  "traceTaskLifecycleState",
		required:  []string{"tasks", "pendingForks", "lifecyclePending", "commandTargetPID", "lifecycleExited"},
		forbidden: architectureOwnerForbiddenTokens,
	},
	{
		name:      "attach completion",
		file:      "cmd/strace-go/event_attach_state.go",
		typeName:  "traceAttachState",
		required:  []string{"targets", "exitReader", "readerEnabled"},
		forbidden: architectureOwnerForbiddenTokens,
	},
	{
		name:      "FD state",
		file:      "cmd/strace-go/fd_state_store.go",
		typeName:  "FDStateStore",
		required:  []string{"paths", "offsets", "fdStates", "fdCloexec"},
		forbidden: architectureOwnerForbiddenTokens,
	},
}

type architectureSessionDependencyContract struct {
	field    string
	typeName string
}

var traceArchitectureSessionDependencyContracts = [...]architectureSessionDependencyContract{
	{field: "HasCommand", typeName: "bool"},
	{field: "CommandWaiter", typeName: "traceCommandWaiter"},
	{field: "Events", typeName: "traceRingbufReader"},
	{field: "TargetPID", typeName: "int"},
	{field: "SyscallLimit", typeName: "uint64"},
	{field: "EventPolicy", typeName: "traceEventPolicyOwner"},
	{field: "OutputPolicy", typeName: "traceOutputPolicyOwner"},
	{field: "Catalog", typeName: "meta.CatalogPort"},
	{field: "Decoder", typeName: "handler.SnapshotDecoder"},
	{field: "FDState", typeName: "traceFDStateOwner"},
	{field: "Runtime", typeName: "handler.RuntimeServices"},
	{field: "OutWriter", typeName: "io.Writer"},
	{field: "Output", typeName: "traceFinalizerOutput"},
	{field: "Summary", typeName: "traceSummaryOwner"},
	{field: "TimeFormatter", typeName: "traceTimeFormatter"},
	{field: "StackTraces", typeName: "traceStackTraceReader"},
	{field: "Stats", typeName: "traceStatsReader"},
	{field: "Resolver", typeName: "traceSymbolResolver"},
	{field: "State", typeName: "traceStateOwner"},
	{field: "Clock", typeName: "traceClock"},
	{field: "SyscallMetadata", typeName: "*syscallMetadataTable"},
}

func TestArchitectureContractCatalogHasEntries(t *testing.T) {
	if len(traceArchitecturePortContracts) == 0 {
		t.Fatal("architecture port contract catalog is empty")
	}
	if len(traceArchitectureStateOwnerContracts) == 0 {
		t.Fatal("architecture state owner contract catalog is empty")
	}
}

func TestArchitecturePortContractsAreBackedBySource(t *testing.T) {
	seen := make(map[string]bool, len(traceArchitecturePortContracts))
	for _, contract := range traceArchitecturePortContracts {
		if contract.name == "" || seen[contract.name] {
			t.Fatalf("duplicate or empty architecture port contract %q", contract.name)
		}
		seen[contract.name] = true
		port := readArchitectureSource(t, contract.portFile)
		if !hasArchitectureInterface(port, contract.portType) {
			t.Fatalf("%s does not declare interface %s", contract.portFile, contract.portType)
		}
		owner := readArchitectureSource(t, contract.ownerFile)
		if !hasArchitectureStruct(owner, contract.ownerType) {
			t.Fatalf("%s does not declare owner struct %s", contract.ownerFile, contract.ownerType)
		}
		if contract.ownerAssertion != "" && !strings.Contains(string(port), contract.ownerAssertion) {
			t.Fatalf("%s is missing owner assertion %q", contract.portFile, contract.ownerAssertion)
		}
		composition := readArchitectureSource(t, contract.compositionFile)
		for _, token := range contract.compositionTokens {
			if !strings.Contains(string(composition), token) {
				t.Fatalf("%s is missing composition contract %q", contract.compositionFile, token)
			}
		}
	}
}

func TestArchitectureStateOwnersKeepDomainMapsOutOfCoordinator(t *testing.T) {
	coordinator := readArchitectureSource(t, "cmd/strace-go/event_state.go")
	fields := architectureStructFields(t, coordinator, "TraceState")
	for _, required := range []string{"correlation", "unfinished", "lifecycle", "attach"} {
		if !fields[required] {
			t.Fatalf("TraceState is missing owner field %q", required)
		}
	}
	forbidden := []string{
		"pendingSyscalls", "pendingExits", "pendingExecArgs", "suspendedSyscalls",
		"unqueued", "inFlight", "tasks", "pendingForks", "lifecyclePending",
		"commandTargetPID", "lifecycleExited", "targets", "exitReader", "readerEnabled",
	}
	for _, field := range forbidden {
		if fields[field] {
			t.Fatalf("TraceState directly owns domain field %q", field)
		}
	}
}

func TestArchitectureStateOwnerContractsDeclareTheirStorage(t *testing.T) {
	for _, contract := range traceArchitectureStateOwnerContracts {
		source := readArchitectureSource(t, contract.file)
		text := string(source)
		for _, forbidden := range contract.forbidden {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s owner contains forbidden runtime dependency %q", contract.name, forbidden)
			}
		}
		fields := architectureStructFields(t, source, contract.typeName)
		for _, required := range contract.required {
			if !fields[required] {
				t.Fatalf("%s owner %s is missing field %q", contract.name, contract.typeName, required)
			}
		}
	}
}

func TestTraceSessionDependencyMatrixMatchesCompositionBoundary(t *testing.T) {
	source := readArchitectureSource(t, "cmd/strace-go/session_composition.go")
	actual := architectureStructFieldTypes(t, source, "traceSessionDeps")
	if len(actual) != len(traceArchitectureSessionDependencyContracts) {
		t.Fatalf("traceSessionDeps fields = %d, contract entries = %d", len(actual), len(traceArchitectureSessionDependencyContracts))
	}
	for _, contract := range traceArchitectureSessionDependencyContracts {
		got, ok := actual[contract.field]
		if !ok {
			t.Fatalf("traceSessionDeps is missing dependency %q", contract.field)
		}
		if got != contract.typeName {
			t.Fatalf("traceSessionDeps.%s type = %q, want %q", contract.field, got, contract.typeName)
		}
	}
}

func TestArchitectureEventReaderHasOneSynchronousSink(t *testing.T) {
	path := "cmd/strace-go/event_reader.go"
	source := readArchitectureSource(t, path)
	fields := architectureStructFields(t, source, "TraceEventReader")
	if !fields["reader"] || !fields["decoder"] || !fields["sink"] || !fields["stats"] {
		t.Fatalf("%s does not expose the complete synchronous reader boundary", path)
	}
	if !strings.Contains(string(source), "r.sink.Handle(envelope)") {
		t.Fatalf("%s does not route decoded events through its single sink", path)
	}
	if strings.Contains(string(source), "go r.sink") || strings.Contains(string(source), "go func") {
		t.Fatalf("%s introduces an asynchronous event sink", path)
	}
}

func readArchitectureSource(t *testing.T, relative string) []byte {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), relative)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read architecture source %s: %v", relative, err)
	}
	return source
}

func hasArchitectureInterface(source []byte, name string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "architecture.go", source, 0)
	if err != nil {
		return false
	}
	return architectureType(file, name, true)
}

func hasArchitectureStruct(source []byte, name string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "architecture.go", source, 0)
	if err != nil {
		return false
	}
	return architectureType(file, name, false)
}

func architectureType(file *ast.File, name string, wantInterface bool) bool {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			_, isInterface := typeSpec.Type.(*ast.InterfaceType)
			_, isStruct := typeSpec.Type.(*ast.StructType)
			return (wantInterface && isInterface) || (!wantInterface && isStruct)
		}
	}
	return false
}

func architectureStructFields(t *testing.T, source []byte, name string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "architecture.go", source, 0)
	if err != nil {
		t.Fatalf("parse architecture source: %v", err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", name)
			}
			fields := make(map[string]bool)
			for _, field := range structType.Fields.List {
				for _, fieldName := range field.Names {
					fields[fieldName.Name] = true
				}
			}
			return fields
		}
	}
	t.Fatalf("struct %s is missing", name)
	return nil
}

func architectureStructFieldTypes(t *testing.T, source []byte, name string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "architecture.go", source, 0)
	if err != nil {
		t.Fatalf("parse architecture source: %v", err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", name)
			}
			fields := make(map[string]string)
			for _, field := range structType.Fields.List {
				var rendered bytes.Buffer
				if err := format.Node(&rendered, fset, field.Type); err != nil {
					t.Fatalf("format field type in %s: %v", name, err)
				}
				for _, fieldName := range field.Names {
					fields[fieldName.Name] = rendered.String()
				}
			}
			return fields
		}
	}
	t.Fatalf("struct %s is missing", name)
	return nil
}
