package resurgo

import "slices"

// endbr64 is the byte encoding of the ENDBR64 instruction (F3 0F 1E FA),
// emitted by gcc/clang at every indirect-branch-target function entry when
// -fcf-protection=branch (Intel CET/IBT) is enabled.
var endbr64Bytes = [4]byte{0xf3, 0x0f, 0x1e, 0xfa}

// filterAlignedEntriesCETAMD64 drops aligned-entry candidates that do not
// start with ENDBR64, when the binary appears to use Intel CET/IBT.
//
// On CET-enabled binaries every indirect-branch-target function entry is
// preceded by the ENDBR64 instruction. An aligned address inside a function
// body that is merely reached by a backward jump or NOP padding will never
// carry ENDBR64. This makes ENDBR64 presence a near-perfect discriminator
// for aligned-entry false positives.
//
// CET detection heuristic: if at least one aligned-entry candidate has ENDBR64
// at its address, the binary is treated as CET-enabled. Coincidental occurrence
// of the four-byte ENDBR64 sequence at a 16-byte-aligned address after padding
// in a non-CET binary is astronomically unlikely, so this single-hit threshold
// is safe.
//
// For non-CET binaries (no ENDBR64 found among aligned-entry candidates) the
// slice is returned unchanged, preserving the original recall on older or
// non-hardened binaries.
//
// Candidates detected by prologue analysis or call-site edges
// (DetectionPrologueOnly, DetectionCallTarget, DetectionBoth) are never
// affected: they carry independent evidence and are kept regardless.
//
// textBytes is the raw content of the .text section; textVA is the virtual
// address of its first byte. The function only inspects candidates whose
// DetectionType is DetectionAlignedEntry.
func filterAlignedEntriesCETAMD64(candidates []FunctionCandidate, textBytes []byte, textVA uint64) []FunctionCandidate {
	hasENDBR64 := func(va uint64) bool {
		if va < textVA {
			return false
		}
		off := va - textVA
		if off+4 > uint64(len(textBytes)) {
			return false
		}
		return [4]byte(textBytes[off:off+4]) == endbr64Bytes
	}

	// Determine whether the binary uses CET by counting how many aligned-entry
	// candidates start with ENDBR64. A threshold of 5 is used rather than 1
	// because non-CET binaries can have a handful of CRT helper functions
	// (__do_global_dtors_aux, frame_dummy) that carry ENDBR64 even when the
	// application itself is not compiled with -fcf-protection. Those account
	// for at most 2-4 incidental hits; 5 or more reliable indicates a binary
	// where the compiler emits ENDBR64 at all function entries.
	const cetMinHits = 5
	cetHits := 0
	for i := range candidates {
		if candidates[i].DetectionType == DetectionAlignedEntry && hasENDBR64(candidates[i].Address) {
			cetHits++
			if cetHits >= cetMinHits {
				break
			}
		}
	}
	if cetHits < cetMinHits {
		return candidates
	}

	// CET binary: keep only aligned-entry candidates that have ENDBR64.
	// All other detection types are kept unconditionally.
	result := candidates[:0]
	for _, c := range candidates {
		if c.DetectionType == DetectionAlignedEntry && !hasENDBR64(c.Address) {
			continue
		}
		result = append(result, c)
	}
	return result
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
// DetectionBoth) - signals strong enough to treat as a reliable function
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
			c.DetectionType == DetectionBoth {
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
