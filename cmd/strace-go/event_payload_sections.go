package main

import (
	"encoding/base64"

	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func payloadSectionsForRawPayloadEvent(raw rawPayloadEvent, _ meta.Syscall) []handler.PayloadSection {
	if sections, ok := payloadTLVSectionsForRaw(raw); ok {
		return sections
	}
	return nil
}

func jsonPayloadSections(sections []handler.PayloadSection) []jsonPayloadSection {
	if len(sections) == 0 {
		return nil
	}
	out := make([]jsonPayloadSection, 0, len(sections))
	for _, section := range sections {
		out = append(out, jsonPayloadSection{
			Kind:       string(section.Kind),
			Direction:  string(section.Direction),
			ArgIndex:   section.ArgIndex,
			UserPtr:    section.UserPtr,
			UserLen:    section.UserLen,
			CopiedLen:  section.CopiedLen,
			ProbeRet:   section.ProbeRet,
			DataBase64: base64.StdEncoding.EncodeToString(section.Data),
		})
	}
	return out
}
