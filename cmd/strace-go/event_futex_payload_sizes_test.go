package main

const (
	futexPayloadWaitvElemSize = 24
	futexPayloadRequeueSize   = 48
	futexCmdWait              = 0
	futexCmdLockPI            = 6
	futexCmdWaitBitset        = 9
	futexCmdWaitRequeuePI     = 11
	futexCmdLockPI2           = 13
)

func futexHasTimeout(op uint64) bool {
	baseOp := op & 0x7f
	return baseOp == futexCmdWait ||
		baseOp == futexCmdLockPI ||
		baseOp == futexCmdWaitBitset ||
		baseOp == futexCmdWaitRequeuePI ||
		baseOp == futexCmdLockPI2
}
