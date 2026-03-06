package resurgo

import (
	"testing"
)

func TestFilterCandidatesInRanges(t *testing.T) {
	cands := func(addrs ...uint64) []FunctionCandidate {
		out := make([]FunctionCandidate, len(addrs))
		for i, a := range addrs {
			out[i] = FunctionCandidate{Address: a}
		}
		return out
	}

	addrs := func(cs []FunctionCandidate) []uint64 {
		out := make([]uint64, len(cs))
		for i, c := range cs {
			out[i] = c.Address
		}
		return out
	}

	tests := []struct {
		name   string
		input  []FunctionCandidate
		ranges [][2]uint64
		want   []uint64
	}{
		{
			name:   "no ranges keeps all",
			input:  cands(0x100, 0x200, 0x300),
			ranges: nil,
			want:   []uint64{0x100, 0x200, 0x300},
		},
		{
			name:   "empty input",
			input:  cands(),
			ranges: [][2]uint64{{0x100, 0x200}},
			want:   []uint64{},
		},
		{
			name:  "removes candidate inside range",
			input: cands(0x100, 0x150, 0x200),
			ranges: [][2]uint64{
				{0x140, 0x160},
			},
			want: []uint64{0x100, 0x200},
		},
		{
			name:  "lo boundary included hi boundary excluded",
			input: cands(0x100, 0x140, 0x160, 0x200),
			ranges: [][2]uint64{
				{0x140, 0x160},
			},
			want: []uint64{0x100, 0x160, 0x200},
		},
		{
			name:  "multiple ranges",
			input: cands(0x100, 0x200, 0x300, 0x400, 0x500),
			ranges: [][2]uint64{
				{0x180, 0x220},
				{0x380, 0x420},
			},
			want: []uint64{0x100, 0x300, 0x500},
		},
		{
			name:  "all candidates removed",
			input: cands(0x100, 0x110, 0x120),
			ranges: [][2]uint64{
				{0x100, 0x130},
			},
			want: []uint64{},
		},
		{
			name:  "no candidates in range",
			input: cands(0x100, 0x200),
			ranges: [][2]uint64{
				{0x300, 0x400},
			},
			want: []uint64{0x100, 0x200},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterCandidatesInRanges(tt.input, tt.ranges)
			gotAddrs := addrs(got)
			if len(gotAddrs) != len(tt.want) {
				t.Fatalf("len=%d want=%d: got %v want %v",
					len(gotAddrs), len(tt.want), gotAddrs, tt.want)
			}
			for i := range tt.want {
				if gotAddrs[i] != tt.want[i] {
					t.Errorf("[%d] got 0x%x want 0x%x", i, gotAddrs[i], tt.want[i])
				}
			}
		})
	}
}
