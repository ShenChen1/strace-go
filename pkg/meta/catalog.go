package meta

// Catalog is the immutable formatter metadata owned by one trace session.
// Its maps are private so event processing cannot mutate shared xlat state.
type Catalog struct {
	format         string
	tables         map[string]XlatTable
	syscallArgXlat map[string]map[string]string
}

// NewCatalog creates a session-local copy of all generated and runtime xlat metadata.
func NewCatalog(format string) *Catalog {
	catalog := &Catalog{
		format:         normalizeXlatFormat(format),
		tables:         cloneXlatTables(generatedXlatTables),
		syscallArgXlat: cloneSyscallArgXlatMap(generatedSyscallArgXlatMap),
	}
	mergeMissingXlatTables(catalog.tables, bpfRuntimeXlatTables)
	mergeXlatTables(catalog.tables, supplementalXlatTables)
	mergeSyscallArgXlatMap(catalog.syscallArgXlat, supplementalSyscallArgXlatMap)
	return catalog
}

func (c *Catalog) require() {
	if c == nil {
		panic("meta: nil Catalog")
	}
}

// Format returns the normalized xlat output mode for this catalog.
func (c *Catalog) Format() string {
	c.require()
	return c.format
}

// Table returns a copy of the table descriptor. Entries remain read-only by contract.
func (c *Catalog) Table(name string) (XlatTable, bool) {
	c.require()
	table, ok := c.tables[name]
	if !ok {
		return XlatTable{}, false
	}
	return cloneXlatTable(table), true
}

// SyscallArgXlat returns the xlat table mapped to a syscall argument.
func (c *Catalog) SyscallArgXlat(syscallName, argName string) (string, bool) {
	c.require()
	args, ok := c.syscallArgXlat[syscallName]
	if !ok {
		return "", false
	}
	xlatName, ok := args[argName]
	return xlatName, ok
}

// DecodeFlags translates a value using this session's xlat catalog and mode.
func (c *Catalog) DecodeFlags(val uint64, xlatName string) string {
	c.require()
	return (&flagDecoder{catalog: c}).decodeFlags(val, xlatName)
}

func normalizeXlatFormat(format string) string {
	switch format {
	case "raw", "abbrev", "verbose":
		return format
	default:
		return "abbrev"
	}
}

func cloneXlatTables(source map[string]XlatTable) map[string]XlatTable {
	clone := make(map[string]XlatTable, len(source))
	for name, table := range source {
		clone[name] = cloneXlatTable(table)
	}
	return clone
}

func cloneXlatTable(table XlatTable) XlatTable {
	return XlatTable{
		Prefix:  table.Prefix,
		Entries: append([]XlatVal(nil), table.Entries...),
	}
}

func cloneSyscallArgXlatMap(source map[string]map[string]string) map[string]map[string]string {
	clone := make(map[string]map[string]string, len(source))
	for syscallName, args := range source {
		clone[syscallName] = make(map[string]string, len(args))
		for argName, xlatName := range args {
			clone[syscallName][argName] = xlatName
		}
	}
	return clone
}

func mergeMissingXlatTables(target, source map[string]XlatTable) {
	for name, table := range source {
		if _, exists := target[name]; !exists {
			target[name] = cloneXlatTable(table)
		}
	}
}

func mergeXlatTables(target, source map[string]XlatTable) {
	for name, table := range source {
		target[name] = cloneXlatTable(table)
	}
}

func mergeSyscallArgXlatMap(target, source map[string]map[string]string) {
	for syscallName, args := range source {
		if target[syscallName] == nil {
			target[syscallName] = make(map[string]string, len(args))
		}
		for argName, xlatName := range args {
			target[syscallName][argName] = xlatName
		}
	}
}
