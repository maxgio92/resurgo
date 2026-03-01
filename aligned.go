package resurgo

import (
	"golang.org/x/arch/x86/x86asm"
)

// alignedEntryAlignment is the function alignment GCC and Clang emit by
// default on x86-64 (-falign-functions=16).
const alignedEntryAlignment = 16

// DetectionAlignedEntry indicates the candidate was found by alignment-
// boundary analysis: a ret/jmp terminator followed by NOP padding ending
// at a 16-byte aligned address.
const DetectionAlignedEntry DetectionType = "aligned-entry"

// detectAlignedEntriesAMD64 scans the code for the pattern emitted by
// compilers to separate adjacent functions:
//
//	<terminator>          ; ret (0xC3) or jmp
//	<nop padding>...      ; 1 or more NOP-like fill bytes
//	<aligned address>     ; 16-byte boundary - likely a new function entry
//
// It returns the virtual addresses of all such aligned boundaries. These are
// low-confidence candidates: the pattern is necessary but not sufficient to
// confirm a function entry (alignment padding can also appear inside functions
// at loop-head alignment points, though that is much less common at 16-byte
// granularity after a ret).
func detectAlignedEntriesAMD64(code []byte, baseAddr uint64) []uint64 {
	var entries []uint64

	i := 0
	for i < len(code) {
		// Skip ENDBR64 / ENDBR32 transparently.
		if i+4 <= len(code) &&
			code[i] == 0xf3 && code[i+1] == 0x0f &&
			code[i+2] == 0x1e && (code[i+3] == 0xfa || code[i+3] == 0xfb) {
			i += 4
			continue
		}

		inst, err := x86asm.Decode(code[i:], 64)
		if err != nil {
			i++
			continue
		}

		// RET/LRET are the primary terminators. Unconditional JMP is also
		// included as a terminator for inter-function tail calls, but only
		// when the jump target is backwards (target < source): intra-function
		// branches inside a loop body are invariably forward jumps (they skip
		// over a code block or jump back to the loop head after alignment),
		// whereas tail calls to PLT stubs or sibling functions almost always
		// jump backward relative to the caller's address range.
		isTerminator := inst.Op == x86asm.RET || inst.Op == x86asm.LRET
		if inst.Op == x86asm.JMP {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				targetVA := baseAddr + uint64(i) + uint64(inst.Len) + uint64(int64(rel))
				sourceVA := baseAddr + uint64(i)
				if targetVA < sourceVA {
					isTerminator = true // backward jmp: likely an inter-function tail call
				}
			}
		}

		if !isTerminator {
			i += inst.Len
			continue
		}

		// Found a RET. Advance past it and consume NOP padding.
		j := i + inst.Len
		for j < len(code) {
			// INT3 (0xCC) is used by some compilers as inter-function padding.
			if code[j] == 0xcc {
				j++
				continue
			}

			pad, err := x86asm.Decode(code[j:], 64)
			if err != nil {
				break
			}
			if !isNOPLike(pad) {
				break
			}
			j += pad.Len
		}

		// Reject if no padding was consumed: a bare RET immediately followed
		// by code is intra-function (e.g. a base-case branch target).
		if j == i+inst.Len {
			i += inst.Len
			continue
		}

		if j >= len(code) {
			break
		}

		addr := baseAddr + uint64(j)
		if addr%alignedEntryAlignment != 0 {
			i += inst.Len
			continue
		}

		// Reject if the instruction at the aligned boundary is itself a
		// terminator: this indicates an intra-function base-case return
		// (e.g. factorial's jle→ret path) rather than a new function entry.
		boundary, err := x86asm.Decode(code[j:], 64)
		if err == nil && (boundary.Op == x86asm.RET || boundary.Op == x86asm.LRET) {
			i += inst.Len
			continue
		}

		entries = append(entries, addr)

		i += inst.Len
	}

	return entries
}

// isNOPLike reports whether inst is a NOP-class instruction used as padding:
// - Any NOP (single or multi-byte Intel NOP family)
// - XCHG AX, AX (0x66 0x90, a 2-byte NOP equivalent)
// - CS/DATA16 prefix sequences that decode as NOP variants
func isNOPLike(inst x86asm.Inst) bool {
	if inst.Op == x86asm.NOP {
		return true
	}
	// XCHG AX, AX (66 90) decodes as XCHG with AX,AX operands - a canonical
	// 2-byte NOP. Accept any XCHG where both operands are the same register.
	if inst.Op == x86asm.XCHG {
		if inst.Args[0] == inst.Args[1] {
			return true
		}
	}
	return false
}
