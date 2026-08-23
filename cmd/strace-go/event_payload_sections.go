package main

import (
	"encoding/base64"

	"strace-go/pkg/handler"
)

func payloadSectionsForRawPayloadEvent(raw rawPayloadEvent) []handler.PayloadSection {
	return payloadSectionsForRawPayloadEventInto(raw, nil)
}

func payloadSectionsForRawPayloadEventInto(
	raw rawPayloadEvent,
	dst *[]handler.PayloadSection,
) []handler.PayloadSection {
	if sections, ok := payloadTLVSectionsForRawInto(raw, dst); ok {
		return sections
	}
	return nil
}

func jsonPayloadSections(sections []handler.PayloadSection) []jsonPayloadSection {
	return jsonPayloadSectionsInto(nil, sections)
}

func jsonPayloadSectionsInto(
	dst []jsonPayloadSection,
	sections []handler.PayloadSection,
) []jsonPayloadSection {
	if len(sections) == 0 {
		return nil
	}
	dst = resizeJSONPayloadSections(dst, len(sections))
	for i, section := range sections {
		dst[i] = newJSONPayloadSection(section)
		dst[i].DataBase64 = base64.StdEncoding.EncodeToString(section.Data)
	}
	return dst
}

func jsonPayloadSectionsIntoRaw(
	dst []jsonPayloadSection,
	sections []handler.PayloadSection,
) []jsonPayloadSection {
	if len(sections) == 0 {
		return nil
	}
	dst = resizeJSONPayloadSections(dst, len(sections))
	for i, section := range sections {
		dst[i] = newJSONPayloadSection(section)
		dst[i].rawData = section.Data
	}
	return dst
}

func resizeJSONPayloadSections(dst []jsonPayloadSection, length int) []jsonPayloadSection {
	if cap(dst) < length {
		return make([]jsonPayloadSection, length)
	}
	return dst[:length]
}

func newJSONPayloadSection(section handler.PayloadSection) jsonPayloadSection {
	return jsonPayloadSection{
		Kind:      string(section.Kind),
		Direction: string(section.Direction),
		ArgIndex:  section.ArgIndex,
		UserPtr:   section.UserPtr,
		UserLen:   section.UserLen,
		CopiedLen: section.CopiedLen,
		ProbeRet:  section.ProbeRet,
	}
}
