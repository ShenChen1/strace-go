package format

// FlagDecoder translates flag values without exposing metadata storage.
type FlagDecoder interface {
	DecodeFlags(value uint64, tableName string) string
}

// XlatCatalog exposes both flag decoding and the selected xlat output mode.
type XlatCatalog interface {
	FlagDecoder
	Format() string
}
