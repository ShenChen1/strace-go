package main

type captureProgramArray string

const (
	captureProgramArrayEnter   captureProgramArray = "enter"
	captureProgramArrayExit    captureProgramArray = "exit"
	captureProgramArrayRecvmsg captureProgramArray = "recvmsg"
	captureProgramArrayMmsg    captureProgramArray = "mmsg_bytes"
)

type captureProgramKind string

const (
	captureProgramTailCall   captureProgramKind = "tail_call"
	captureProgramStandalone captureProgramKind = "standalone"
)

type captureProgramRef struct {
	array   captureProgramArray
	program string
}

type captureProgramSpec struct {
	array        captureProgramArray
	slot         uint32
	goName       string
	cName        string
	programName  string
	familyGoName string
	kind         captureProgramKind
	direct       bool
	dependencies []captureProgramRef
}

type captureRouteSpec struct {
	syscallName           string
	enterProgram          string
	exitProgram           string
	standaloneExitElision bool
}

type captureAuxRootSpec struct {
	syscallName  string
	programs     []string
	programRefs  []captureProgramRef
	recvmsgProbe bool
}

type captureManifest struct {
	routeMapMaxEntries uint32
	programs           []captureProgramSpec
	routes             []captureRouteSpec
	auxRoots           []captureAuxRootSpec
}

func newCaptureManifest() captureManifest {
	return captureManifest{
		routeMapMaxEntries: 512,
		programs:           captureProgramSpecs(),
		routes:             captureRouteSpecs(),
		auxRoots:           captureAuxRootSpecs(),
	}
}
