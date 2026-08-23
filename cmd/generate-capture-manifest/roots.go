package main

func captureAuxRootSpecs() []captureAuxRootSpec {
	return []captureAuxRootSpec{
		{
			syscallName:  "recvmsg",
			programs:     []string{"trace_kretprobe_recvmsg_dispatch"},
			recvmsgProbe: true,
			programRefs: []captureProgramRef{
				{array: captureProgramArrayRecvmsg, program: "trace_kretprobe_recvmsg_name"},
				{array: captureProgramArrayRecvmsg, program: "trace_kretprobe_recvmsg_control"},
				{array: captureProgramArrayRecvmsg, program: "trace_kretprobe_recvmsg_final"},
			},
		},
		{
			syscallName: "sendmmsg",
			programRefs: []captureProgramRef{
				{array: captureProgramArrayMmsg, program: "enter_mmsg_bytes0"},
				{array: captureProgramArrayMmsg, program: "enter_mmsg_bytes1"},
				{array: captureProgramArrayMmsg, program: "enter_mmsg_bytes2"},
				{array: captureProgramArrayMmsg, program: "enter_mmsg_bytes3"},
			},
		},
	}
}
