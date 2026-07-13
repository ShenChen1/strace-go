package handler

import "errors"

type fetchPolicyMemoryReader struct {
	data  []byte
	reads int
}

func (r *fetchPolicyMemoryReader) Read(int, uint64, int) ([]byte, error) {
	r.reads++
	if r.data == nil {
		return nil, errors.New("unreadable address")
	}
	return append([]byte(nil), r.data...), nil
}
