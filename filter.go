package resurgo

import (
	"debug/elf"
	"slices"
)

// CandidateFilter applies an ELF-aware transformation to a candidate slice.
// Each filter reads only what it needs from f and returns the updated slice.
type CandidateFilter func([]FunctionCandidate, *elf.File) ([]FunctionCandidate, error)

// elfFilters is the ordered list of ELF-specific candidate filters applied by
// DetectFunctionsFromELF after the disassembly pipeline. Each strategy
// registers its filter here; order matters.
var elfFilters = []CandidateFilter{
	pltFilter,
	ehFrameFilter,
}

// pltFilter removes candidates that land inside linker-generated PLT sections.
func pltFilter(cs []FunctionCandidate, f *elf.File) ([]FunctionCandidate, error) {
	var pltRanges [][2]uint64
	for _, name := range []string{".plt", ".plt.got", ".plt.sec", ".iplt"} {
		if sec := f.Section(name); sec != nil {
			pltRanges = append(pltRanges, [2]uint64{sec.Addr, sec.Addr + sec.Size})
		}
	}
	return filterCandidatesInRanges(cs, pltRanges), nil
}

// filterCandidatesInRanges removes candidates whose addresses fall within any
// of the given address ranges. Each range is a [lo, hi) pair.
//
// Used to discard candidates that land inside linker-generated sections (e.g.
// PLT stubs) that the call-site scanner can detect as CALL/JMP targets even
// though they are not real function entries in the binary under analysis.
func filterCandidatesInRanges(candidates []FunctionCandidate, ranges [][2]uint64) []FunctionCandidate {
	if len(ranges) == 0 {
		return candidates
	}
	result := candidates[:0]
	for _, c := range candidates {
		inRange := false
		for _, r := range ranges {
			if c.Address >= r[0] && c.Address < r[1] {
				inRange = true
				break
			}
		}
		if !inRange {
			result = append(result, c)
		}
	}
	return result
}

// filterJumpTargetsByAnchorRange removes DetectionJumpTarget candidates that
// are intra-function branch targets from the candidates map.
//
// An anchor is a candidate confirmed by a CALL instruction
// (DetectionCallTarget) or a prologue pattern (DetectionPrologueOnly,
// DetectionPrologueCallSite) - signals strong enough to treat as a reliable function
// start. Consecutive anchor addresses define function body intervals.
//
// A JumpTarget candidate is removed only when it falls strictly between two
// consecutive anchors AND every source address in JumpedFrom also falls
// within that same interval. Both conditions must hold: the target is inside
// a known function body, and every jump that reaches it originates from
// within the same body (switch dispatch, basic block jump).
//
// If JumpedFrom is empty the source is unknown, so the candidate is kept.
// If any source falls outside the interval the jump is inter-function (e.g.
// a tail call from another function), so the candidate is kept.
//
// Aligned-entry candidates are intentionally excluded: small leaf functions
// with no call-site or prologue signal have no enclosing anchor and would
// be incorrectly discarded.
func filterJumpTargetsByAnchorRange(candidates map[uint64]*FunctionCandidate) {
	anchors := make([]uint64, 0, len(candidates))
	for addr, c := range candidates {
		if c.DetectionType == DetectionCallTarget ||
			c.DetectionType == DetectionPrologueOnly ||
			c.DetectionType == DetectionPrologueCallSite {
			anchors = append(anchors, addr)
		}
	}
	slices.Sort(anchors)

	for addr, c := range candidates {
		if c.DetectionType != DetectionJumpTarget {
			continue
		}
		idx, found := slices.BinarySearch(anchors, addr)
		if found {
			continue // addr is itself an anchor
		}
		if idx == 0 || idx >= len(anchors) {
			continue // outside all anchor intervals
		}
		// addr falls strictly between anchors[idx-1] and anchors[idx].
		// Only remove if every source is within the same interval: that
		// means the jump originates from within the same function body
		// (intra-function branch). Any source outside the interval means
		// a different function is jumping here (inter-function tail call).
		lower, upper := anchors[idx-1], anchors[idx]
		allIntra := len(c.JumpedFrom) > 0
		for _, src := range c.JumpedFrom {
			if src < lower || src >= upper {
				allIntra = false
				break
			}
		}
		if allIntra {
			delete(candidates, addr)
		}
	}
}

