package main

import (
	"fmt"
	"strings"
)

func (r *TextRenderer) PrintSignalEvent(view signalEventView, signalName string) {
	fields := []string{"si_signo=" + signalName}
	if view.error != 0 {
		fields = append(fields, fmt.Sprintf("si_errno=%d", view.error))
	}
	codeName := signalCodeName(view.code)
	if codeName == "" {
		codeName = fmt.Sprintf("%d", view.code)
	}
	fields = append(fields, "si_code="+codeName)
	if signalCodeHasSender(view.code) {
		fields = append(fields,
			fmt.Sprintf("si_pid=%d", view.senderPID),
			fmt.Sprintf("si_uid=%d", view.senderUID),
		)
	}
	fmt.Fprintf(r.out, "%s%s--- %s {%s} ---\n",
		r.timePrefix(view.enterTime), r.pidPrefix(int(view.tid)), signalName, strings.Join(fields, ", "))
}
