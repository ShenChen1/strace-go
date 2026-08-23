package main

import "strace-go/pkg/handler"

const tracePayloadStorageMaxRetainedBytes = 64 << 10

// tracePayloadStorage owns copied payload bytes until the synchronous event
// route releases the pending state. merged is only a temporary view and may
// contain borrowed Ringbuf data.
type tracePayloadStorage struct {
	sections []handler.PayloadSection
	merged   []handler.PayloadSection
}

func (storage *tracePayloadStorage) reset() {
	if storage == nil {
		return
	}
	for i := range storage.sections {
		data := storage.sections[i].Data
		if cap(data) > tracePayloadStorageMaxRetainedBytes {
			data = nil
		} else if data != nil {
			data = data[:0]
		}
		storage.sections[i] = handler.PayloadSection{Data: data}
	}
	clear(storage.merged)
	storage.sections = storage.sections[:0]
	storage.merged = storage.merged[:0]
}

func (storage *tracePayloadStorage) copyFrom(sections []handler.PayloadSection) {
	if storage == nil {
		return
	}
	storage.reset()
	for _, section := range sections {
		storage.appendOwned(section)
	}
}

func (storage *tracePayloadStorage) appendOwned(section handler.PayloadSection) {
	if storage == nil {
		return
	}
	index := len(storage.sections)
	if index == cap(storage.sections) {
		storage.sections = append(storage.sections, handler.PayloadSection{})
	} else {
		storage.sections = storage.sections[:index+1]
	}
	data := storage.sections[index].Data
	storage.sections[index] = section
	if len(section.Data) == 0 {
		storage.sections[index].Data = data[:0]
		return
	}
	storage.sections[index].Data = append(data[:0], section.Data...)
}

func (storage *tracePayloadStorage) mergeView(
	current []handler.PayloadSection,
) []handler.PayloadSection {
	if storage == nil {
		return current
	}
	if len(current) == 0 {
		return storage.sections
	}
	storage.merged = storage.merged[:0]
	for _, section := range storage.sections {
		if hasEquivalentPayloadSection(current, section) {
			continue
		}
		storage.merged = append(storage.merged, section)
	}
	storage.merged = append(storage.merged, current...)
	return storage.merged
}

func payloadSectionsFromStorage(storage *tracePayloadStorage) []handler.PayloadSection {
	if storage == nil {
		return nil
	}
	return storage.sections
}

func (c *traceSyscallCorrelationState) acquirePayloadStorage() *tracePayloadStorage {
	if c == nil {
		return &tracePayloadStorage{}
	}
	last := len(c.reusablePayload) - 1
	if last < 0 {
		return &tracePayloadStorage{}
	}
	storage := c.reusablePayload[last]
	c.reusablePayload = c.reusablePayload[:last]
	return storage
}

func (c *traceSyscallCorrelationState) releasePayloadStorage(storage *tracePayloadStorage) {
	if c == nil || storage == nil {
		return
	}
	storage.reset()
	c.reusablePayload = append(c.reusablePayload, storage)
}

func (c *traceSyscallCorrelationState) copyPayloadSectionsIntoStorage(
	sections []handler.PayloadSection,
) *tracePayloadStorage {
	if len(sections) == 0 {
		return nil
	}
	storage := c.acquirePayloadStorage()
	storage.copyFrom(sections)
	return storage
}

func (c *traceSyscallCorrelationState) mergePayloadSectionsIntoStorage(
	storage *tracePayloadStorage,
	next []handler.PayloadSection,
) *tracePayloadStorage {
	if len(next) == 0 {
		return storage
	}
	if storage == nil {
		storage = c.acquirePayloadStorage()
	}
	for _, section := range next {
		if hasEquivalentPayloadSection(storage.sections, section) {
			continue
		}
		storage.appendOwned(section)
	}
	return storage
}
