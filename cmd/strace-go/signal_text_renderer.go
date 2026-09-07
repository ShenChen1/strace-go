package main

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func (r *TextRenderer) PrintSignalEvent(view signalEventView, signalName string) {
	r.selectOutputPID(int(view.tid))
	stack := r.readStackSnapshot(view.stackID)
	fields := []string{"si_signo=" + signalName}
	if view.error != 0 {
		fields = append(fields, fmt.Sprintf("si_errno=%d", view.error))
	}
	codeName := signalCodeName(signalName, view.code)
	if codeName == "" {
		codeName = fmt.Sprintf("%d", view.code)
	}
	fields = append(fields, "si_code="+codeName)
	if signalCodeHasSender(signalName, view.code) {
		fields = append(fields,
			fmt.Sprintf("si_pid=%d", view.senderPID),
			fmt.Sprintf("si_uid=%d", view.senderUID),
		)
	}
	if signalName == "SIGCHLD" {
		fields = append(fields,
			"si_status="+formatChildSignalStatus(view.code, view.status),
			fmt.Sprintf("si_utime=%d", view.userTime),
			fmt.Sprintf("si_stime=%d", view.systemTime),
		)
	}
	if signalName == "SIGSEGV" && view.code > 0 {
		fields = append(fields, fmt.Sprintf("si_addr=%#x", view.address))
	}
	fmt.Fprintf(r.out, "%s%s%s--- %s {%s} ---\n",
		r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)),
		r.instructionPointerPrefix(stack), signalName, strings.Join(fields, ", "))
	r.printStackTrace(stack)
}

func formatChildSignalStatus(code int32, status int32) string {
	if code == 1 {
		return fmt.Sprintf("%d", status)
	}
	if name := unix.SignalName(syscall.Signal(status)); name != "" {
		return name
	}
	return fmt.Sprintf("%d", status)
}
