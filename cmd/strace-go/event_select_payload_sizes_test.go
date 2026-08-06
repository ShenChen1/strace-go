package main

const selectPayloadTimeoutSize = 16

func selectFdSetUserLen(nfds uint64) uint32 {
	nfds32 := int32(nfds)
	if nfds32 <= 0 {
		return 0
	}
	if nfds32 > int32(selectPayloadFdSetSize*8) {
		return selectPayloadFdSetSize
	}
	return uint32((nfds32 + 7) / 8)
}
