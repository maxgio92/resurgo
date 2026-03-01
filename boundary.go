package resurgo

import (
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	// alignedEntryAlignment is the function alignment GCC and Clang emit by
	// default on x86-64 (-falign-functions=16).
	alignedEntryAlignment = 16

	// DetectionAlignedEntry indicates the candidate was found by alignment-
	// boundary analysis: a ret/jmp terminator followed by NOP padding ending
	// at a 16-byte aligned address.
	DetectionAlignedEntry DetectionType = "aligned-entry"
)

// detectAlignedEntriesAMD64 scans raw x86-64 machine code bytes for the
// pattern emitted by compilers to separate adjacent functions. code is the
// raw bytes of the executable section; baseAddr is the virtual address
// corresponding to the first byte of code.
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
			// undecoded byte, skip
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
				sourceVA := baseAddr + uint64(i)
				targetVA := sourceVA + uint64(inst.Len) + uint64(int64(rel))
				if targetVA < sourceVA {
					isTerminator = true // backward jmp: likely an inter-function tail call
				}
			}
		}

		if !isTerminator {
			i += inst.Len
			// not a function boundary, keep scanning
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
				// undecoded byte, end of padding
				break
			}
			if !isNOPLike(pad) {
				// first non-NOP: padding is done
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

		// j now points to the first byte after the NOP padding. If it has
		// reached the end of the section, the padding runs to the end of
		// .text with no instruction following it - nothing to emit.
		if j >= len(code) {
			break
		}

		addr := baseAddr + uint64(j)
		// boundary not 16-byte aligned, not a function entry
		if addr%alignedEntryAlignment != 0 {
			i += inst.Len
			continue
		}

		// Reject if the instruction at the aligned boundary is itself a
		// terminator: this indicates an intra-function base-case return
		// (e.g. factorial's jle→ret path) rather than a new function entry.
		boundary, err := x86asm.Decode(code[j:], 64)
		if err != nil {
			// undecoded boundary instruction, skip
			i += inst.Len
			continue
		}
		if boundary.Op == x86asm.RET || boundary.Op == x86asm.LRET {
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

// detectAlignedEntriesARM64 applies the same boundary-separator strategy as
// detectAlignedEntriesAMD64 to AArch64 code. code is the raw bytes of the
// executable section; baseAddr is the virtual address corresponding to the
// first byte of code.
//
// The pattern is identical in structure but simpler to scan because all
// AArch64 instructions are exactly 4 bytes:
//
//	<terminator>          ; RET or backward B (tail call)
//	<nop padding>...      ; one or more NOP instructions (0xD503201F)
//	<aligned address>     ; 16-byte boundary - likely a new function entry
//
// The NOP requirement filters out tight packing between small leaf functions
// that share a cache line with no alignment fill (e.g. a 2-instruction leaf
// directly followed by the next function at the next 4-byte boundary).
// Requiring at least one NOP before the boundary is the same threshold that
// makes this signal meaningful on AMD64.
func detectAlignedEntriesARM64(code []byte, baseAddr uint64) []uint64 {
	var entries []uint64

	const insnLen = 4

	for i := 0; i+insnLen <= len(code); i += insnLen {
		inst, err := arm64asm.Decode(code[i : i+insnLen])
		if err != nil {
			// undecoded instruction, skip
			continue
		}

		// RET is the primary terminator. Backward unconditional B is a tail
		// call to a sibling or PLT stub and qualifies as a terminator.
		isTerminator := inst.Op == arm64asm.RET
		if inst.Op == arm64asm.B {
			if pcrel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				sourceVA := baseAddr + uint64(i)
				targetVA := sourceVA + uint64(int64(pcrel))
				if targetVA < sourceVA {
					isTerminator = true
				}
			}
		}

		if !isTerminator {
			// not a function boundary, keep scanning
			continue
		}

		// Consume NOP padding after the terminator.
		j := i + insnLen
		for j+insnLen <= len(code) {
			pad, err := arm64asm.Decode(code[j : j+insnLen])
			if err != nil {
				// undecoded instruction, end of padding
				break
			}
			if pad.Op != arm64asm.NOP {
				// first non-NOP: padding is done
				break
			}
			j += insnLen
		}

		// On ARM64, tight packing without NOP padding is normal: small leaf
		// functions are frequently placed back-to-back on 4-byte boundaries
		// without alignment fill. A ret immediately followed by a 16-byte
		// aligned address is still a meaningful boundary signal because
		// intra-function code reaches such alignment far less often than
		// inter-function boundaries do.
		//
		// j now points to the first byte after any NOP padding. If it has
		// reached the end of the section, the padding runs to the end of
		// .text with no instruction following it - nothing to emit.
		if j+insnLen > len(code) {
			break
		}

		addr := baseAddr + uint64(j)
		// boundary not 16-byte aligned, not a function entry
		if addr%alignedEntryAlignment != 0 {
			continue
		}

		// Reject if the boundary instruction is RET: this is an intra-function
		// base-case return landing on an aligned address, not a new entry.
		boundary, err := arm64asm.Decode(code[j : j+insnLen])
		if err != nil {
			// undecoded boundary instruction, skip
			continue
		}
		if boundary.Op == arm64asm.RET {
			continue
		}

		entries = append(entries, addr)
	}

	return entries
}
