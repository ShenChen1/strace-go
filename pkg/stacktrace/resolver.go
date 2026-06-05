package stacktrace

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type MapRegion struct {
	Start  uint64
	End    uint64
	Offset uint64
	Path   string
}

type Symbol struct {
	Name  string
	Value uint64
}

type elfInfo struct {
	syms  []Symbol
	progs []elf.ProgHeader
}

type Resolver struct {
	pid     int
	regions []MapRegion
	elfMap  map[string]*elfInfo
	mu      sync.Mutex
}

func NewResolver(pid int) *Resolver {
	r := &Resolver{
		pid:    pid,
		elfMap: make(map[string]*elfInfo),
	}
	r.refreshMaps()
	return r
}

func (r *Resolver) refreshMaps() {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return
	}
	defer f.Close()

	var regions []MapRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		path := parts[5]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		addrs := strings.Split(parts[0], "-")
		if len(addrs) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(addrs[0], 16, 64)
		end, _ := strconv.ParseUint(addrs[1], 16, 64)
		offset, _ := strconv.ParseUint(parts[2], 16, 64)
		regions = append(regions, MapRegion{Start: start, End: end, Offset: offset, Path: path})
	}
	r.regions = regions
}

func (r *Resolver) getElfInfo(path string) *elfInfo {
	if info, ok := r.elfMap[path]; ok {
		return info
	}
	f, err := elf.Open(path)
	if err != nil {
		r.elfMap[path] = nil
		return nil
	}
	defer f.Close()

	info := &elfInfo{}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			info.progs = append(info.progs, prog.ProgHeader)
		}
	}

	syms, _ := f.Symbols()
	dynSyms, _ := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	var res []Symbol
	for _, s := range syms {
		if s.Value != 0 && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			res = append(res, Symbol{Name: s.Name, Value: s.Value})
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Value < res[j].Value
	})
	info.syms = res

	r.elfMap[path] = info
	return info
}

func (r *Resolver) Resolve(ip uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var region *MapRegion
	for i := range r.regions {
		if ip >= r.regions[i].Start && ip < r.regions[i].End {
			region = &r.regions[i]
			break
		}
	}
	if region == nil {
		r.refreshMaps()
		for i := range r.regions {
			if ip >= r.regions[i].Start && ip < r.regions[i].End {
				region = &r.regions[i]
				break
			}
		}
	}
	if region == nil {
		return fmt.Sprintf("[0x%x]", ip)
	}

	fileOffset := ip - region.Start + region.Offset
	info := r.getElfInfo(region.Path)

	if info != nil {
		var vaddr uint64 = fileOffset
		foundVaddr := false
		for _, prog := range info.progs {
			if prog.Off <= fileOffset && fileOffset < prog.Off+prog.Filesz {
				vaddr = fileOffset - prog.Off + prog.Vaddr
				foundVaddr = true
				break
			}
		}
		if !foundVaddr {
			// fallback
			vaddr = fileOffset
		}

		syms := info.syms
		idx := sort.Search(len(syms), func(i int) bool {
			return syms[i].Value > vaddr
		})
		if idx > 0 {
			sym := syms[idx-1]
			offset := vaddr - sym.Value
			return fmt.Sprintf("%s(%s+0x%x) [0x%x]", region.Path, sym.Name, offset, ip)
		}
		return fmt.Sprintf("%s(+0x%x) [0x%x]", region.Path, fileOffset, ip)
	}

	return fmt.Sprintf("%s(+0x%x) [0x%x]", region.Path, fileOffset, ip)
}
