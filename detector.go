package resurgo

import (
	"cmp"
	"debug/elf"
	"fmt"
	"io"
	"slices"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// DetectFunctions combines prologue detection, call site analysis, and
// alignment-based boundary detection to identify function entry points.
// Functions detected by multiple methods receive higher confidence ratings.
func DetectFunctions(code []byte, baseAddr uint64, arch Arch) ([]FunctionCandidate, error) {
	// Detect prologues
	prologues, err := DetectPrologues(code, baseAddr, arch)
	if err != nil {
		return nil, fmt.Errorf("failed to detect prologues: %w", err)
	}

	// Detect call sites
	edges, err := DetectCallSites(code, baseAddr, arch)
	if err != nil {
		return nil, fmt.Errorf("failed to detect call sites: %w", err)
	}

	// Build a map of function candidates by address
	candidates := make(map[uint64]*FunctionCandidate)

	// Add prologue-based candidates
	for _, p := range prologues {
		candidates[p.Address] = &FunctionCandidate{
			Address:       p.Address,
			DetectionType: DetectionPrologueOnly,
			PrologueType:  p.Type,
			Confidence:    ConfidenceMedium, // Will be upgraded if also a call target
		}
	}

	// Process call site edges - include both high-confidence (direct calls)
	// and medium-confidence (unconditional jumps, which may be tail calls).
	for _, edge := range edges {
		if edge.Confidence != ConfidenceHigh && edge.Confidence != ConfidenceMedium {
			continue
		}

		candidate, exists := candidates[edge.TargetAddr]
		if exists {
			// Address has both prologue and is called/jumped to - highest confidence
			candidate.DetectionType = DetectionBoth
			candidate.Confidence = ConfidenceHigh
			if edge.Type == CallSiteCall {
				candidate.CalledFrom = append(candidate.CalledFrom, edge.SourceAddr)
			} else {
				candidate.JumpedFrom = append(candidate.JumpedFrom, edge.SourceAddr)
			}
		} else {
			// New candidate from call site analysis only
			detType := DetectionCallTarget
			if edge.Type == CallSiteJump {
				detType = DetectionJumpTarget
			}

			calledFrom := []uint64{}
			jumpedFrom := []uint64{}
			if edge.Type == CallSiteCall {
				calledFrom = []uint64{edge.SourceAddr}
			} else {
				jumpedFrom = []uint64{edge.SourceAddr}
			}

			candidates[edge.TargetAddr] = &FunctionCandidate{
				Address:       edge.TargetAddr,
				DetectionType: detType,
				CalledFrom:    calledFrom,
				JumpedFrom:    jumpedFrom,
				Confidence:    ConfidenceMedium, // Call/jump target but no prologue
			}
		}
	}

	// Add alignment-based candidates for functions that have no prologue and
	// no call-site signal (e.g. pure-leaf functions with external linkage
	// that were never called due to inlining or compile-time evaluation).
	//
	// These receive ConfidenceLow because the pattern (ret + NOP padding →
	// 16-byte aligned address) is reliable for function separators but can
	// also match intra-function alignment at loop heads.
	var alignedEntries []uint64
	switch arch {
	case ArchAMD64:
		alignedEntries = detectAlignedEntriesAMD64(code, baseAddr)
	case ArchARM64:
		alignedEntries = detectAlignedEntriesARM64(code, baseAddr)
	}
	for _, addr := range alignedEntries {
		if _, exists := candidates[addr]; !exists {
			candidates[addr] = &FunctionCandidate{
				Address:       addr,
				DetectionType: DetectionAlignedEntry,
				Confidence:    ConfidenceLow,
			}
		}
	}

	// Convert map to sorted slice
	result := make([]FunctionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, *candidate)
	}

	slices.SortFunc(result, func(a, b FunctionCandidate) int {
		return cmp.Compare(a.Address, b.Address)
	})

	return result, nil
}

// DetectFunctionsFromELF parses an ELF binary from the given reader, extracts
// the .text section, and returns detected function candidates using combined
// prologue detection, call site analysis, and alignment-based boundary detection.
// The architecture is inferred from the ELF header.
func DetectFunctionsFromELF(r io.ReaderAt) ([]FunctionCandidate, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %w", err)
	}
	defer f.Close()

	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("no .text section found")
	}

	code, err := textSec.Data()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read .text section: %w", err)
	}

	switch f.Machine {
	case elf.EM_X86_64:
		return DetectFunctions(code, textSec.Addr, ArchAMD64)
	case elf.EM_AARCH64:
		return DetectFunctions(code, textSec.Addr, ArchARM64)
	default:
		return nil, fmt.Errorf("unsupported ELF machine: %s", f.Machine)
	}
}

// DetectPrologues analyzes raw machine code bytes and returns detected function
// prologues. baseAddr is the virtual address corresponding to the start of code.
// arch selects the architecture-specific detection logic.
// This function performs no I/O and works with any binary format.
func DetectPrologues(code []byte, baseAddr uint64, arch Arch) ([]Prologue, error) {
	switch arch {
	case ArchAMD64:
		return detectProloguesAMD64(code, baseAddr)
	case ArchARM64:
		return detectProloguesARM64(code, baseAddr)
	default:
		return nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
}

func detectProloguesAMD64(code []byte, baseAddr uint64) ([]Prologue, error) {
	var result []Prologue

	offset := 0
	addr := baseAddr
	var prevInsn *x86asm.Inst

	for offset < len(code) {
		// Skip ENDBR64 (f3 0f 1e fa) and ENDBR32 (f3 0f 1e fb) which
		// golang.org/x/arch/x86/x86asm does not recognise. These CET
		// instructions appear at function entries on binaries compiled
		// with -fcf-protection and are transparent to prologue detection.
		if offset+4 <= len(code) &&
			code[offset] == 0xf3 && code[offset+1] == 0x0f &&
			code[offset+2] == 0x1e && (code[offset+3] == 0xfa || code[offset+3] == 0xfb) {
			offset += 4
			addr += 4
			continue // prevInsn intentionally unchanged
		}

		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			offset++
			addr++
			prevInsn = nil
			continue
		}

		// Pattern 1: Classic frame pointer setup - push rbp; mov rbp, rsp
		if prevInsn != nil &&
			prevInsn.Op == x86asm.PUSH && prevInsn.Args[0] == x86asm.RBP &&
			inst.Op == x86asm.MOV && inst.Args[0] == x86asm.RBP && inst.Args[1] == x86asm.RSP {
			result = append(result, Prologue{
				Address:      addr - uint64(prevInsn.Len),
				Type:         PrologueClassic,
				Instructions: "push rbp; mov rbp, rsp",
			})
		}

		// Pattern 2: No-frame-pointer function - sub rsp, imm
		if inst.Op == x86asm.SUB && inst.Args[0] == x86asm.RSP {
			if imm, ok := inst.Args[1].(x86asm.Imm); ok && imm > 0 {
				if prevInsn == nil || prevInsn.Op == x86asm.RET || prevInsn.Op == x86asm.PUSH {
					result = append(result, Prologue{
						Address:      addr,
						Type:         PrologueNoFramePointer,
						Instructions: fmt.Sprintf("sub rsp, 0x%x", int64(imm)),
					})
				}
			}
		}

		// Pattern 3: Push callee-saved register at function boundary
		if inst.Op == x86asm.PUSH {
			if reg, ok := inst.Args[0].(x86asm.Reg); ok && isCalleeSavedAMD64(reg) {
				if prevInsn == nil || prevInsn.Op == x86asm.RET {
					result = append(result, Prologue{
						Address:      addr,
						Type:         ProloguePushOnly,
						Instructions: fmt.Sprintf("push %s", reg),
					})
				}
			}
		}

		// Pattern 4: Stack allocation with lea - lea rsp, [rsp-imm]
		if inst.Op == x86asm.LEA && inst.Args[0] == x86asm.RSP {
			if prevInsn == nil || prevInsn.Op == x86asm.RET {
				result = append(result, Prologue{
					Address:      addr,
					Type:         PrologueLEABased,
					Instructions: "lea rsp, [rsp-offset]",
				})
			}
		}

		prevInsn = &inst
		offset += inst.Len
		addr += uint64(inst.Len)
	}

	return result, nil
}

func isCalleeSavedAMD64(reg x86asm.Reg) bool {
	switch reg {
	case x86asm.RBX, x86asm.RBP, x86asm.R12, x86asm.R13, x86asm.R14, x86asm.R15:
		return true
	}
	return false
}

// isSTPx29x30PreIndex checks if an ARM64 instruction is stp x29, x30, [sp, #-N]!
func isSTPx29x30PreIndex(inst arm64asm.Inst) bool {
	if inst.Op != arm64asm.STP {
		return false
	}
	r0, ok0 := inst.Args[0].(arm64asm.Reg)
	r1, ok1 := inst.Args[1].(arm64asm.Reg)
	mem, ok2 := inst.Args[2].(arm64asm.MemImmediate)
	return ok0 && ok1 && ok2 &&
		r0 == arm64asm.X29 && r1 == arm64asm.X30 &&
		mem.Mode == arm64asm.AddrPreIndex
}

// isMovX29SP checks if an ARM64 instruction is mov x29, sp.
// The disassembler decodes this as MOV with both args as RegSP.
func isMovX29SP(inst arm64asm.Inst) bool {
	if inst.Op != arm64asm.MOV {
		return false
	}
	r0, ok0 := inst.Args[0].(arm64asm.RegSP)
	r1, ok1 := inst.Args[1].(arm64asm.RegSP)
	return ok0 && ok1 && r0 == arm64asm.RegSP(arm64asm.X29) && r1 == arm64asm.RegSP(arm64asm.SP)
}

func detectProloguesARM64(code []byte, baseAddr uint64) ([]Prologue, error) {
	var result []Prologue

	const insnLen = 4
	var prevInsn *arm64asm.Inst

	for offset := 0; offset+insnLen <= len(code); offset += insnLen {
		inst, err := arm64asm.Decode(code[offset : offset+insnLen])
		if err != nil {
			prevInsn = nil
			continue
		}
		addr := baseAddr + uint64(offset)

		if prevInsn != nil && isSTPx29x30PreIndex(*prevInsn) {
			if isMovX29SP(inst) {
				// Pattern 1: STP frame pair - stp x29, x30, [sp, #-N]! ; mov x29, sp
				result = append(result, Prologue{
					Address:      addr - insnLen,
					Type:         PrologueSTPFramePair,
					Instructions: "stp x29, x30, [sp, #-N]!; mov x29, sp",
				})
			} else {
				// Pattern 3: STP-only - stp x29, x30, [sp, #-N]! without mov x29, sp
				result = append(result, Prologue{
					Address:      addr - insnLen,
					Type:         PrologueSTPOnly,
					Instructions: "stp x29, x30, [sp, #-N]!",
				})
			}
		}

		// Pattern 2: STR LR pre-index - str x30, [sp, #-N]! (Go-style prologue)
		if inst.Op == arm64asm.STR {
			if r0, ok := inst.Args[0].(arm64asm.Reg); ok && r0 == arm64asm.X30 {
				if mem, ok := inst.Args[1].(arm64asm.MemImmediate); ok && mem.Mode == arm64asm.AddrPreIndex {
					if prevInsn == nil || prevInsn.Op == arm64asm.RET {
						result = append(result, Prologue{
							Address:      addr,
							Type:         PrologueSTRLRPreIndex,
							Instructions: fmt.Sprintf("str x30, %s", inst.Args[1]),
						})
					}
				}
			}
		}

		// Pattern 3: Sub SP - sub sp, sp, #N (stack allocation without frame pointer)
		if inst.Op == arm64asm.SUB {
			if dst, ok := inst.Args[0].(arm64asm.RegSP); ok && dst == arm64asm.RegSP(arm64asm.SP) {
				if src, ok := inst.Args[1].(arm64asm.RegSP); ok && src == arm64asm.RegSP(arm64asm.SP) {
					if prevInsn == nil || prevInsn.Op == arm64asm.RET {
						result = append(result, Prologue{
							Address:      addr,
							Type:         PrologueSubSP,
							Instructions: fmt.Sprintf("sub sp, sp, #%s", inst.Args[2]),
						})
					}
				}
			}
		}

		prevInsn = &inst
	}

	return result, nil
}

// DetectProloguesFromELF parses an ELF binary from the given reader, extracts
// the .text section, and returns detected function prologues.
// The architecture is inferred from the ELF header.
func DetectProloguesFromELF(r io.ReaderAt) ([]Prologue, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %w", err)
	}
	defer f.Close()

	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("no .text section found")
	}

	code, err := textSec.Data()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read .text section: %w", err)
	}

	switch f.Machine {
	case elf.EM_X86_64:
		return detectProloguesAMD64(code, textSec.Addr)
	case elf.EM_AARCH64:
		return detectProloguesARM64(code, textSec.Addr)
	default:
		return nil, fmt.Errorf("unsupported ELF machine: %s", f.Machine)
	}
}

