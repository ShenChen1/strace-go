package format

import (
	"encoding/binary"
	"testing"
)

func TestUtimesWithXlatSpecialValues(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[0:8], uint64(3735928559))
	binary.LittleEndian.PutUint64(data[8:16], uint64(1073741823))
	binary.LittleEndian.PutUint64(data[16:24], 0xcafef00ddeadbeef)
	binary.LittleEndian.PutUint64(data[24:32], uint64(1073741822))

	tests := []struct {
		name       string
		xlatFormat string
		want       string
	}{
		{
			name:       "abbrev",
			xlatFormat: "abbrev",
			want:       "[UTIME_NOW, UTIME_OMIT]",
		},
		{
			name:       "raw",
			xlatFormat: "raw",
			want:       "[{tv_sec=3735928559, tv_nsec=1073741823}, {tv_sec=-3819351491602432273, tv_nsec=1073741822}]",
		},
		{
			name:       "verbose",
			xlatFormat: "verbose",
			want:       "[{tv_sec=3735928559, tv_nsec=1073741823} /* UTIME_NOW */, {tv_sec=-3819351491602432273, tv_nsec=1073741822} /* UTIME_OMIT */]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UtimesWithXlat(data, tt.xlatFormat); got != tt.want {
				t.Fatalf("UtimesWithXlat() = %q, want %q", got, tt.want)
			}
		})
	}
}
