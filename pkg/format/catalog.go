package format

// FlagDecoder translates flag values without exposing metadata storage.
type FlagDecoder interface {
	DecodeFlags(value uint64, tableName string) string
}
