package resurgo_test

import (
	"debug/elf"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/maxgio92/resurgo"

)

func TestFilterAlignedEntriesCETAMD64(t *testing.T) {
	const textVA = uint64(0x1000)

	endbr64 := []byte{0xf3, 0x0f, 0x1e, 0xfa}

	addrs := func(cs []resurgo.FunctionCandidate) []uint64 {
		out := make([]uint64, len(cs))
		for i, c := range cs {
			out[i] = c.Address
		}
		return out
	}

	// 4 ENDBR64 hits at 0x00-0x30; zeroes at 0x40 and 0x50.
	text1 := make([]byte, 0x60)
	for _, off := range []int{0x00, 0x10, 0x20, 0x30} {
		copy(text1[off:], endbr64)
	}

	// 5 ENDBR64 hits at 0x00-0x40 (triggers CET) and one more at 0x80;
	// zeroes at 0x50, 0x60, 0x70.
	text2 := make([]byte, 0x90)
	for _, off := range []int{0x00, 0x10, 0x20, 0x30, 0x40, 0x80} {
		copy(text2[off:], endbr64)
	}

	tests := []struct {
		name      string
		text      []byte
		input     []resurgo.FunctionCandidate
		wantAddrs []uint64
	}{{
		name: "non-CET binary returns all candidates unchanged",
		text: text1,
		input: []resurgo.FunctionCandidate{
			{Address: 0x1000, DetectionType: resurgo.DetectionAlignedEntry},
			{Address: 0x1010, DetectionType: resurgo.DetectionAlignedEntry},
			{Address: 0x1020, DetectionType: resurgo.DetectionAlignedEntry},
			{Address: 0x1030, DetectionType: resurgo.DetectionAlignedEntry}, // 4 ENDBR64: below threshold
			{Address: 0x1040, DetectionType: resurgo.DetectionAlignedEntry},
			{Address: 0x1050, DetectionType: resurgo.DetectionAlignedEntry},
		},
		wantAddrs: []uint64{0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050},
	}, {
		name: "CET binary drops aligned-entry candidates without ENDBR64",
		text: text2,
		input: []resurgo.FunctionCandidate{
			{Address: 0x1000, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64 - kept
			{Address: 0x1010, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64 - kept
			{Address: 0x1020, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64 - kept
			{Address: 0x1030, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64 - kept
			{Address: 0x1040, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64 - kept (5th, triggers CET)
			{Address: 0x1050, DetectionType: resurgo.DetectionAlignedEntry}, // no ENDBR64 - dropped
			{Address: 0x1060, DetectionType: resurgo.DetectionAlignedEntry}, // no ENDBR64 - dropped
			{Address: 0x1070, DetectionType: resurgo.DetectionPrologueOnly}, // not AlignedEntry - kept
			{Address: 0x1080, DetectionType: resurgo.DetectionAlignedEntry}, // ENDBR64, after threshold - kept
		},
		wantAddrs: []uint64{0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1070, 0x1080},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resurgo.FilterAlignedEntriesCETAMD64(tt.input, tt.text, textVA, 0)
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
	cands := func(addrs ...uint64) []resurgo.FunctionCandidate {
		out := make([]resurgo.FunctionCandidate, len(addrs))
		for i, a := range addrs {
			out[i] = resurgo.FunctionCandidate{Address: a}
		}
		return out
	}

	addrs := func(cs []resurgo.FunctionCandidate) []uint64 {
		out := make([]uint64, len(cs))
		for i, c := range cs {
			out[i] = c.Address
		}
		return out
	}

	tests := []struct {
		name   string
		input  []resurgo.FunctionCandidate
		ranges [][2]uint64
		want   []uint64
	}{{
		name:   "no ranges keeps all",
		input:  cands(0x100, 0x200, 0x300), // three candidates, no exclusion ranges
		ranges: nil,
		want:   []uint64{0x100, 0x200, 0x300},
	}, {
		name:   "empty input",
		input:  cands(),
		ranges: [][2]uint64{{0x100, 0x200}}, // range present but nothing to filter
		want:   []uint64{},
	}, {
		name:  "removes candidate inside range",
		input: cands(0x100, 0x150, 0x200), // 0x150 falls inside [0x140, 0x160)
		ranges: [][2]uint64{
			{0x140, 0x160},
		},
		want: []uint64{0x100, 0x200}, // 0x150 removed
	}, {
		name:  "lo boundary included hi boundary excluded",
		input: cands(0x100, 0x140, 0x160, 0x200), // 0x140 == lo (removed), 0x160 == hi (kept)
		ranges: [][2]uint64{
			{0x140, 0x160}, // half-open interval [lo, hi)
		},
		want: []uint64{0x100, 0x160, 0x200},
	}, {
		name:  "multiple ranges",
		input: cands(0x100, 0x200, 0x300, 0x400, 0x500), // 0x200 in [0x180,0x220), 0x400 in [0x380,0x420)
		ranges: [][2]uint64{
			{0x180, 0x220},
			{0x380, 0x420},
		},
		want: []uint64{0x100, 0x300, 0x500}, // 0x200 and 0x400 removed
	}, {
		name:  "all candidates removed",
		input: cands(0x100, 0x110, 0x120), // all three fall inside [0x100, 0x130)
		ranges: [][2]uint64{
			{0x100, 0x130},
		},
		want: []uint64{},
	}, {
		name:  "no candidates in range",
		input: cands(0x100, 0x200), // candidates below range [0x300, 0x400)
		ranges: [][2]uint64{
			{0x300, 0x400},
		},
		want: []uint64{0x100, 0x200}, // nothing removed
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resurgo.FilterCandidatesInRanges(tt.input, tt.ranges)
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

// TestFilters verifies the behavioral contract of each exported filter against
// a real C ELF binary.
func TestFilters(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found, skipping")
	}

	outPath := filepath.Join(t.TempDir(), "demo-app-c")
	cmd := exec.Command("gcc", "-O0", "-o", outPath, "testdata/demo-app.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile demo-app.c: %v\n%s", err, out)
	}

	f, err := elf.Open(outPath)
	if err != nil {
		t.Fatalf("failed to open ELF: %v", err)
	}
	defer f.Close()

	input, err := resurgo.DisasmDetector(f)
	if err != nil {
		t.Fatalf("resurgo.DisasmDetector: %v", err)
	}

	tests := []struct {
		name   string
		filter resurgo.CandidateFilter
		check  func(t *testing.T, result []resurgo.FunctionCandidate)
	}{{
		name:   "cet",
		filter: resurgo.CETFilter,
		// resurgo.CETFilter must never drop the ELF entry point.
		check: func(t *testing.T, result []resurgo.FunctionCandidate) {
			inputHasEntry := false
			for _, c := range input {
				if c.Address == f.Entry {
					inputHasEntry = true
					break
				}
			}
			if !inputHasEntry {
				return
			}
			for _, c := range result {
				if c.Address == f.Entry {
					return
				}
			}
			t.Errorf("entry point 0x%x was dropped", f.Entry)
		},
	}, {
		name:   "plt",
		filter: resurgo.PLTFilter,
		// resurgo.PLTFilter must remove all candidates inside the .plt section.
		check: func(t *testing.T, result []resurgo.FunctionCandidate) {
			plt := f.Section(".plt")
			if plt == nil {
				t.Skip("no .plt section")
			}
			for _, c := range result {
				if c.Address >= plt.Addr && c.Address < plt.Addr+plt.Size {
					t.Errorf("candidate 0x%x inside PLT [0x%x, 0x%x) was not removed",
						c.Address, plt.Addr, plt.Addr+plt.Size)
				}
			}
		},
	}, {
		name:   "ehframe",
		filter: resurgo.EhFrameFilter,
		// resurgo.EhFrameFilter must retain only FDE-confirmed candidates.
		check: func(t *testing.T, result []resurgo.FunctionCandidate) {
			fde, err := resurgo.EhFrameDetector(f)
			if err != nil {
				t.Fatalf("resurgo.EhFrameDetector: %v", err)
			}
			fdeSet := make(map[uint64]struct{}, len(fde))
			for _, c := range fde {
				fdeSet[c.Address] = struct{}{}
			}
			for _, c := range result {
				if _, ok := fdeSet[c.Address]; !ok {
					t.Errorf("candidate 0x%x kept but not FDE-confirmed", c.Address)
				}
			}
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.filter(input, f)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(result) > len(input) {
				t.Errorf("added candidates: input=%d output=%d", len(input), len(result))
			}
			tt.check(t, result)
		})
	}
}


