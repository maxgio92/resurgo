package resurgo

import (
	"testing"
)

func TestFilterAlignedEntriesCETAMD64(t *testing.T) {
	const textVA = uint64(0x1000)

	endbr64 := []byte{0xf3, 0x0f, 0x1e, 0xfa}

	addrs := func(cs []FunctionCandidate) []uint64 {
		out := make([]uint64, len(cs))
		for i, c := range cs {
			out[i] = c.Address
		}
		return out
	}

	// 4 ENDBR64 hits at 0x00–0x30; zeroes at 0x40 and 0x50.
	text1 := make([]byte, 0x60)
	for _, off := range []int{0x00, 0x10, 0x20, 0x30} {
		copy(text1[off:], endbr64)
	}

	// 5 ENDBR64 hits at 0x00–0x40 (triggers CET) and one more at 0x80;
	// zeroes at 0x50, 0x60, 0x70.
	text2 := make([]byte, 0x90)
	for _, off := range []int{0x00, 0x10, 0x20, 0x30, 0x40, 0x80} {
		copy(text2[off:], endbr64)
	}

	tests := []struct {
		name      string
		text      []byte
		input     []FunctionCandidate
		wantAddrs []uint64
	}{
		{
			name: "non-CET binary returns all candidates unchanged",
			text: text1,
			input: []FunctionCandidate{
				{Address: 0x1000, DetectionType: DetectionAlignedEntry},
				{Address: 0x1010, DetectionType: DetectionAlignedEntry},
				{Address: 0x1020, DetectionType: DetectionAlignedEntry},
				{Address: 0x1030, DetectionType: DetectionAlignedEntry}, // 4 ENDBR64: below threshold
				{Address: 0x1040, DetectionType: DetectionAlignedEntry},
				{Address: 0x1050, DetectionType: DetectionAlignedEntry},
			},
			wantAddrs: []uint64{0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050},
		},
		{
			name: "CET binary drops aligned-entry candidates without ENDBR64",
			text: text2,
			input: []FunctionCandidate{
				{Address: 0x1000, DetectionType: DetectionAlignedEntry}, // ENDBR64 - kept
				{Address: 0x1010, DetectionType: DetectionAlignedEntry}, // ENDBR64 - kept
				{Address: 0x1020, DetectionType: DetectionAlignedEntry}, // ENDBR64 - kept
				{Address: 0x1030, DetectionType: DetectionAlignedEntry}, // ENDBR64 - kept
				{Address: 0x1040, DetectionType: DetectionAlignedEntry}, // ENDBR64 - kept (5th, triggers CET)
				{Address: 0x1050, DetectionType: DetectionAlignedEntry}, // no ENDBR64 - dropped
				{Address: 0x1060, DetectionType: DetectionAlignedEntry}, // no ENDBR64 - dropped
				{Address: 0x1070, DetectionType: DetectionPrologueOnly}, // not AlignedEntry - kept
				{Address: 0x1080, DetectionType: DetectionAlignedEntry}, // ENDBR64, after threshold - kept
			},
			wantAddrs: []uint64{0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1070, 0x1080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterAlignedEntriesCETAMD64(tt.input, tt.text, textVA, 0)
			gotAddrs := addrs(got)
			if len(gotAddrs) != len(tt.wantAddrs) {
				t.Fatalf("len=%d want=%d: got %v want %v",
					len(gotAddrs), len(tt.wantAddrs), gotAddrs, tt.wantAddrs)
			}
			for i := range tt.wantAddrs {
				if gotAddrs[i] != tt.wantAddrs[i] {
					t.Errorf("[%d] got 0x%x want 0x%x", i, gotAddrs[i], tt.wantAddrs[i])
				}
			}
		})
	}
}

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
