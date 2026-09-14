package meta

import "golang.org/x/sys/unix"

// Only actual native ABI differences override the shared symbolic catalog.
func applyNativeXlat(tables map[string]XlatTable) {
	values := map[string]uint64{
		"O_DIRECT": unix.O_DIRECT, "O_DIRECTORY": unix.O_DIRECTORY,
		"O_NOFOLLOW": unix.O_NOFOLLOW, "O_TMPFILE": unix.O_TMPFILE,
		"O_LARGEFILE": nativeRawOLargefile,
	}
	for name, table := range tables {
		entries := table.Entries[:0]
		for _, entry := range table.Entries {
			if nativeExcludedXlatNames[entry.Str] {
				continue
			}
			if value, ok := values[entry.Str]; ok {
				entry.Val = value
			}
			// The shared table contains both the raw bit and its O_DIRECTORY alias.
			if entry.Str == "__O_TMPFILE" && entry.Val != rawOTmpfile {
				entry.Val = unix.O_TMPFILE
			}
			entries = append(entries, entry)
		}
		table.Entries = append(entries, nativeXlatAdditions[name]...)
		tables[name] = table
	}
}

const rawOTmpfile = 0x400000
