package main

import "strace-go/pkg/handler"

const kvmRunIOCTL uint64 = 0xae80

var kvmExitReasonNames = [...]string{
	"KVM_EXIT_UNKNOWN",
	"KVM_EXIT_EXCEPTION",
	"KVM_EXIT_IO",
	"KVM_EXIT_HYPERCALL",
	"KVM_EXIT_DEBUG",
	"KVM_EXIT_HLT",
	"KVM_EXIT_MMIO",
	"KVM_EXIT_IRQ_WINDOW_OPEN",
	"KVM_EXIT_SHUTDOWN",
	"KVM_EXIT_FAIL_ENTRY",
	"KVM_EXIT_INTR",
	"KVM_EXIT_SET_TPR",
	"KVM_EXIT_TPR_ACCESS",
	"KVM_EXIT_S390_SIEIC",
	"KVM_EXIT_S390_RESET",
	"KVM_EXIT_DCR",
	"KVM_EXIT_NMI",
	"KVM_EXIT_INTERNAL_ERROR",
	"KVM_EXIT_OSI",
	"KVM_EXIT_PAPR_HCALL",
	"KVM_EXIT_S390_UCONTROL",
	"KVM_EXIT_WATCHDOG",
	"KVM_EXIT_S390_TSCH",
	"KVM_EXIT_EPR",
	"KVM_EXIT_SYSTEM_EVENT",
	"KVM_EXIT_S390_STSI",
	"KVM_EXIT_IOAPIC_EOI",
	"KVM_EXIT_HYPERV",
	"KVM_EXIT_ARM_NISV",
	"KVM_EXIT_X86_RDMSR",
	"KVM_EXIT_X86_WRMSR",
	"KVM_EXIT_DIRTY_RING_FULL",
	"KVM_EXIT_AP_RESET_HOLD",
	"KVM_EXIT_X86_BUS_LOCK",
	"KVM_EXIT_XEN",
	"KVM_EXIT_RISCV_SBI",
	"KVM_EXIT_RISCV_CSR",
	"KVM_EXIT_NOTIFY",
	"KVM_EXIT_LOONGARCH_IOCSR",
	"KVM_EXIT_MEMORY_FAULT",
	"KVM_EXIT_TDX",
	"KVM_EXIT_ARM_SEA",
	"KVM_EXIT_ARM_LDST64B",
	"KVM_EXIT_SNP_REQ_CERTS",
}

func decorateKVMResult(
	result handler.Result,
	syscallName string,
	view syscallEventView,
) handler.Result {
	if syscallName != "ioctl" || view.eventType != bpfEventTypeExit ||
		view.ret < 0 || view.args[1] != kvmRunIOCTL ||
		view.eventFlags&bpfEventFlagKVMExit == 0 {
		return result
	}
	description := kvmExitReasonName(view.kvmExitReason)
	if result.ReturnDesc == "" {
		result.ReturnDesc = description
	} else {
		result.ReturnDesc += ", " + description
	}
	return result
}

func kvmExitReasonName(reason uint32) string {
	if reason < uint32(len(kvmExitReasonNames)) {
		return kvmExitReasonNames[reason]
	}
	return "KVM_EXIT_???"
}
