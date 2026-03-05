package resurgo

import "slices"

// filterJumpTargetsByAnchorRange removes DetectionJumpTarget candidates that
// fall strictly between two consecutive anchor function starts from the
// candidates map.
//
// An anchor is a candidate confirmed by a CALL instruction
// (DetectionCallTarget) or a prologue pattern (DetectionPrologueOnly,
// DetectionBoth) - signals strong enough to treat as a reliable function
// start. Any JumpTarget candidate that falls strictly between two consecutive
// anchors is almost certainly the target of an intra-function unconditional
// branch (switch dispatch, basic block jump) rather than a separate function
// entry, and is removed.
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
		if idx > 0 && idx < len(anchors) {
			// addr falls strictly between anchors[idx-1] and anchors[idx]:
			// intra-function jump target, not a function entry.
			delete(candidates, addr)
		}
	}
}
