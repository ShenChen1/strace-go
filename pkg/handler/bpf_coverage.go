package handler

type bpfCommandDecoder uint8

const (
	bpfDecodeMapCreate bpfCommandDecoder = iota + 1
	bpfDecodeMapLookup
	bpfDecodeMapUpdate
	bpfDecodeMapDelete
	bpfDecodeMapNextKey
	bpfDecodeProgLoad
	bpfDecodeObjPin
	bpfDecodeProgAttach
	bpfDecodeProgTestRun
	bpfDecodeObjInfo
	bpfDecodeProgQuery
	bpfDecodeRawTracepoint
	bpfDecodeBtfLoad
	bpfDecodeTaskFDQuery
	bpfDecodeMapFreeze
	bpfDecodeNextID
	bpfDecodeGetFDByID
	bpfDecodeEnableStats
	bpfDecodeIterCreate
	bpfDecodeLinkDetach
	bpfDecodeProgBindMap
	bpfDecodeTokenCreate
	bpfDecodeStreamRead
	bpfDecodeLinkCreate
	bpfDecodeLinkUpdate
	bpfDecodeProgAssocStructOps
	bpfDecodeMapBatch
)

type bpfCommandEvidence uint8

const (
	bpfEvidenceFixtureSuccess bpfCommandEvidence = 1 << iota
	bpfEvidenceFixtureFailure
	bpfEvidenceSemanticSuccess
	bpfEvidenceSemanticFailure
	bpfEvidenceCapabilityBoundary
)

type bpfCommandCapability uint8

const (
	bpfCommandCapabilityStable bpfCommandCapability = iota + 1
	bpfCommandCapabilityEnvironmentDependent
)

type bpfCommandContract string

const (
	bpfContractAttrIn             bpfCommandContract = "attr-in"
	bpfContractAttrInKeyIn        bpfCommandContract = "attr-in+key-in"
	bpfContractAttrInKeyValueIn   bpfCommandContract = "attr-in+key/value-in"
	bpfContractAttrInNestedIn     bpfCommandContract = "attr-in+nested-in"
	bpfContractAttrInPathIn       bpfCommandContract = "attr-in+path-in"
	bpfContractAttrInNameIn       bpfCommandContract = "attr-in+name-in"
	bpfContractAttrInBTFIn        bpfCommandContract = "attr-in+btf-in"
	bpfContractAttrInBatchIn      bpfCommandContract = "attr-in+batch-in"
	bpfContractAttrInKeysIn       bpfCommandContract = "attr-in+keys-in"
	bpfContractNone               bpfCommandContract = "none"
	bpfContractValueOut           bpfCommandContract = "value-out"
	bpfContractNextKeyOut         bpfCommandContract = "next-key-out"
	bpfContractVerifierLogFailure bpfCommandContract = "verifier-log-on-failure"
	bpfContractDataContextOut     bpfCommandContract = "data/context-out"
	bpfContractScalarOut          bpfCommandContract = "scalar-out"
	bpfContractInfoOut            bpfCommandContract = "info-out"
	bpfContractArraysOut          bpfCommandContract = "arrays-out"
	bpfContractLogFailure         bpfCommandContract = "log-out-on-failure"
	bpfContractAttrBufOut         bpfCommandContract = "attr/buf-out"
	bpfContractBatchOut           bpfCommandContract = "batch-out"
	bpfContractStreamBufOut       bpfCommandContract = "stream-buf-out"
)

type bpfCommandCoverage struct {
	name          string
	decoder       bpfCommandDecoder
	enterContract bpfCommandContract
	exitContract  bpfCommandContract
	evidence      string
	evidenceFlags bpfCommandEvidence
	capability    bpfCommandCapability
}

func validBpfCommandContract(contract bpfCommandContract) bool {
	switch contract {
	case bpfContractAttrIn, bpfContractAttrInKeyIn, bpfContractAttrInKeyValueIn,
		bpfContractAttrInNestedIn, bpfContractAttrInPathIn, bpfContractAttrInNameIn,
		bpfContractAttrInBTFIn, bpfContractAttrInBatchIn, bpfContractAttrInKeysIn,
		bpfContractNone, bpfContractValueOut, bpfContractNextKeyOut,
		bpfContractVerifierLogFailure, bpfContractDataContextOut, bpfContractScalarOut,
		bpfContractInfoOut, bpfContractArraysOut, bpfContractLogFailure,
		bpfContractAttrBufOut, bpfContractBatchOut, bpfContractStreamBufOut:
		return true
	default:
		return false
	}
}

// bpfCommandCoverageTable is indexed by the stable BPF command number.
// The decoder and ownership contracts are kept together so a new command
// cannot be added to text formatting without recording its event boundary.
var bpfCommandCoverageTable = [...]bpfCommandCoverage{
	{name: "BPF_MAP_CREATE", decoder: bpfDecodeMapCreate, enterContract: "attr-in", exitContract: "none", evidence: "map-create", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_LOOKUP_ELEM", decoder: bpfDecodeMapLookup, enterContract: "attr-in+key-in", exitContract: "value-out", evidence: "map-lookup", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_UPDATE_ELEM", decoder: bpfDecodeMapUpdate, enterContract: "attr-in+key/value-in", exitContract: "none", evidence: "map-update", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_DELETE_ELEM", decoder: bpfDecodeMapDelete, enterContract: "attr-in+key-in", exitContract: "none", evidence: "map-delete", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_GET_NEXT_KEY", decoder: bpfDecodeMapNextKey, enterContract: "attr-in+key-in", exitContract: "next-key-out", evidence: "map-next-key", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_LOAD", decoder: bpfDecodeProgLoad, enterContract: "attr-in+nested-in", exitContract: "verifier-log-on-failure", evidence: "prog-load", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_OBJ_PIN", decoder: bpfDecodeObjPin, enterContract: "attr-in+path-in", exitContract: "none", evidence: "obj-path", evidenceFlags: bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_OBJ_GET", decoder: bpfDecodeObjPin, enterContract: "attr-in+path-in", exitContract: "none", evidence: "obj-path", evidenceFlags: bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_ATTACH", decoder: bpfDecodeProgAttach, enterContract: "attr-in", exitContract: "none", evidence: "prog-attach", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_DETACH", decoder: bpfDecodeProgAttach, enterContract: "attr-in", exitContract: "none", evidence: "prog-attach", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_TEST_RUN", decoder: bpfDecodeProgTestRun, enterContract: "attr-in+nested-in", exitContract: "data/context-out", evidence: "prog-test-run", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_GET_NEXT_ID", decoder: bpfDecodeNextID, enterContract: "attr-in", exitContract: "scalar-out", evidence: "next-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_GET_NEXT_ID", decoder: bpfDecodeNextID, enterContract: "attr-in", exitContract: "scalar-out", evidence: "next-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_GET_FD_BY_ID", decoder: bpfDecodeGetFDByID, enterContract: "attr-in", exitContract: "none", evidence: "fd-by-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_GET_FD_BY_ID", decoder: bpfDecodeGetFDByID, enterContract: "attr-in", exitContract: "none", evidence: "fd-by-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_OBJ_GET_INFO_BY_FD", decoder: bpfDecodeObjInfo, enterContract: "attr-in", exitContract: "info-out", evidence: "obj-info", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_QUERY", decoder: bpfDecodeProgQuery, enterContract: "attr-in", exitContract: "arrays-out", evidence: "prog-query", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_RAW_TRACEPOINT_OPEN", decoder: bpfDecodeRawTracepoint, enterContract: "attr-in+name-in", exitContract: "none", evidence: "raw-tracepoint", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_BTF_LOAD", decoder: bpfDecodeBtfLoad, enterContract: "attr-in+btf-in", exitContract: "log-out-on-failure", evidence: "btf-load", evidenceFlags: bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_BTF_GET_FD_BY_ID", decoder: bpfDecodeGetFDByID, enterContract: "attr-in", exitContract: "none", evidence: "fd-by-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_TASK_FD_QUERY", decoder: bpfDecodeTaskFDQuery, enterContract: "attr-in", exitContract: "attr/buf-out", evidence: "task-fd-query", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_LOOKUP_AND_DELETE_ELEM", decoder: bpfDecodeMapLookup, enterContract: "attr-in+key-in", exitContract: "value-out", evidence: "map-lookup", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_FREEZE", decoder: bpfDecodeMapFreeze, enterContract: "attr-in", exitContract: "none", evidence: "map-freeze", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_BTF_GET_NEXT_ID", decoder: bpfDecodeNextID, enterContract: "attr-in", exitContract: "scalar-out", evidence: "next-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_LOOKUP_BATCH", decoder: bpfDecodeMapBatch, enterContract: "attr-in", exitContract: "batch-out", evidence: "map-batch", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_LOOKUP_AND_DELETE_BATCH", decoder: bpfDecodeMapBatch, enterContract: "attr-in", exitContract: "batch-out", evidence: "map-batch", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_UPDATE_BATCH", decoder: bpfDecodeMapBatch, enterContract: "attr-in+batch-in", exitContract: "none", evidence: "map-batch", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_MAP_DELETE_BATCH", decoder: bpfDecodeMapBatch, enterContract: "attr-in+keys-in", exitContract: "none", evidence: "map-batch", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_LINK_CREATE", decoder: bpfDecodeLinkCreate, enterContract: "attr-in+nested-in", exitContract: "none", evidence: "link-create", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_LINK_UPDATE", decoder: bpfDecodeLinkUpdate, enterContract: "attr-in", exitContract: "none", evidence: "link-update", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_LINK_GET_FD_BY_ID", decoder: bpfDecodeGetFDByID, enterContract: "attr-in", exitContract: "none", evidence: "fd-by-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_LINK_GET_NEXT_ID", decoder: bpfDecodeNextID, enterContract: "attr-in", exitContract: "scalar-out", evidence: "next-id", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_ENABLE_STATS", decoder: bpfDecodeEnableStats, enterContract: "attr-in", exitContract: "none", evidence: "enable-stats", evidenceFlags: bpfEvidenceCapabilityBoundary, capability: bpfCommandCapabilityEnvironmentDependent},
	{name: "BPF_ITER_CREATE", decoder: bpfDecodeIterCreate, enterContract: "attr-in", exitContract: "none", evidence: "iter-create", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary, capability: bpfCommandCapabilityEnvironmentDependent},
	{name: "BPF_LINK_DETACH", decoder: bpfDecodeLinkDetach, enterContract: "attr-in", exitContract: "none", evidence: "link-detach", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure, capability: bpfCommandCapabilityStable},
	{name: "BPF_PROG_BIND_MAP", decoder: bpfDecodeProgBindMap, enterContract: "attr-in", exitContract: "none", evidence: "prog-bind-map", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceSemanticSuccess, capability: bpfCommandCapabilityStable},
	{name: "BPF_TOKEN_CREATE", decoder: bpfDecodeTokenCreate, enterContract: "attr-in", exitContract: "none", evidence: "token-create", evidenceFlags: bpfEvidenceFixtureFailure | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary, capability: bpfCommandCapabilityEnvironmentDependent},
	{name: "BPF_PROG_STREAM_READ_BY_FD", decoder: bpfDecodeStreamRead, enterContract: "attr-in", exitContract: "stream-buf-out", evidence: "stream-read", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary, capability: bpfCommandCapabilityEnvironmentDependent},
	{name: "BPF_PROG_ASSOC_STRUCT_OPS", decoder: bpfDecodeProgAssocStructOps, enterContract: "attr-in", exitContract: "none", evidence: "prog-assoc-struct-ops", evidenceFlags: bpfEvidenceFixtureSuccess | bpfEvidenceFixtureFailure | bpfEvidenceSemanticSuccess | bpfEvidenceSemanticFailure | bpfEvidenceCapabilityBoundary, capability: bpfCommandCapabilityEnvironmentDependent},
}

func bpfCommandCoverageFor(cmd uint64) (bpfCommandCoverage, bool) {
	if cmd >= uint64(len(bpfCommandCoverageTable)) {
		return bpfCommandCoverage{}, false
	}
	spec := bpfCommandCoverageTable[cmd]
	return spec, spec.name != ""
}
