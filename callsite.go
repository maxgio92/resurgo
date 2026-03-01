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

// CallSiteType represents the type of call site instruction.
type CallSiteType string

// Recognized call site instruction types.
const (
	CallSiteCall CallSiteType = "call"
	CallSiteJump CallSiteType = "jump"
)

// AddressingMode represents how the target address is specified.
type AddressingMode string

// Recognized addressing modes for call site instructions.
const (
	AddressingModePCRelative       AddressingMode = "pc-relative"
	AddressingModeAbsolute         AddressingMode = "absolute"
	AddressingModeRegisterIndirect AddressingMode = "register-indirect"
)

// Confidence represents the reliability of a call site detection.
type Confidence string

// Confidence levels for call site detection.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// CallSiteEdge represents a detected call site (call or jump to a function).
type CallSiteEdge struct {
	SourceAddr  uint64          `json:"source_addr"`
	TargetAddr  uint64          `json:"target_addr"`
	Type        CallSiteType `json:"type"`
	AddressMode AddressingMode  `json:"address_mode"`
	Confidence  Confidence      `json:"confidence"`
}

// DetectionType represents how a function was detected.
type DetectionType string

// Recognized detection types.
const (
	DetectionPrologueOnly DetectionType = "prologue-only"
	DetectionCallTarget   DetectionType = "call-target"
	DetectionJumpTarget   DetectionType = "jump-target"
	DetectionBoth         DetectionType = "both" // Prologue + called/jumped to
)

// FunctionCandidate represents a potential function detected through
// one or more signals (prologue detection, call site analysis, or both).
type FunctionCandidate struct {
	Address       uint64        `json:"address"`
	DetectionType DetectionType `json:"detection_type"`
	PrologueType  PrologueType  `json:"prologue_type,omitempty"`
	CalledFrom    []uint64      `json:"called_from,omitempty"`
	JumpedFrom    []uint64      `json:"jumped_from,omitempty"`
	Confidence    Confidence    `json:"confidence"`
}

// DetectCallSites analyzes raw machine code bytes and returns detected
// call sites (CALL and JMP instructions with their targets). baseAddr is the
// virtual address corresponding to the start of code. arch selects the
// architecture-specific detection logic. This function performs no I/O and
// works with any binary format.
func DetectCallSites(code []byte, baseAddr uint64, arch Arch) ([]CallSiteEdge, error) {
	switch arch {
	case ArchAMD64:
		return detectCallSitesAMD64(code, baseAddr)
	case ArchARM64:
		return detectCallSitesARM64(code, baseAddr)
	default:
		return nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
}

// DetectCallSitesFromELF parses an ELF binary from the given reader, extracts
// the .text section, and returns detected call sites.
// The architecture is inferred from the ELF header.
func DetectCallSitesFromELF(r io.ReaderAt) ([]CallSiteEdge, error) {
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

	var edges []CallSiteEdge
	switch f.Machine {
	case elf.EM_X86_64:
		edges, err = detectCallSitesAMD64(code, textSec.Addr)
	case elf.EM_AARCH64:
		edges, err = detectCallSitesARM64(code, textSec.Addr)
	default:
		return nil, fmt.Errorf("unsupported ELF machine: %s", f.Machine)
	}

	if err != nil {
		return nil, err
	}

	// Filter edges to only include targets within the .text section
	filtered := make([]CallSiteEdge, 0, len(edges))
	textStart := textSec.Addr
	textEnd := textSec.Addr + textSec.Size
	for _, edge := range edges {
		// Only include edges with resolvable targets within .text
		if edge.Confidence != ConfidenceNone &&
			edge.TargetAddr >= textStart &&
			edge.TargetAddr < textEnd {
			filtered = append(filtered, edge)
		}
	}

	return filtered, nil
}

// DetectFunctions combines prologue detection and call site analysis to identify
// function entry points with higher confidence. Functions detected by both methods
// receive the highest confidence rating.
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

	// Process call site edges  - include both high-confidence (direct calls)
	// and medium-confidence (unconditional jumps, which may be tail calls).
	for _, edge := range edges {
		if edge.Confidence != ConfidenceHigh && edge.Confidence != ConfidenceMedium {
			continue
		}

		candidate, exists := candidates[edge.TargetAddr]
		if exists {
			// Address has both prologue and is called/jumped to  - highest confidence
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
	if arch == ArchAMD64 {
		for _, addr := range detectAlignedEntriesAMD64(code, baseAddr) {
			if _, exists := candidates[addr]; !exists {
				candidates[addr] = &FunctionCandidate{
					Address:       addr,
					DetectionType: DetectionAlignedEntry,
					Confidence:    ConfidenceLow,
				}
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
// prologue detection and call site analysis.
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

func detectCallSitesAMD64(code []byte, baseAddr uint64) ([]CallSiteEdge, error) {
	var result []CallSiteEdge

	offset := 0
	addr := baseAddr

	for offset < len(code) {
		// Skip ENDBR64 (f3 0f 1e fa) and ENDBR32 (f3 0f 1e fb) which
		// golang.org/x/arch/x86/x86asm does not recognise. These CET
		// instructions appear at function entries on binaries compiled
		// with -fcf-protection and are transparent to call site detection.
		if offset+4 <= len(code) &&
			code[offset] == 0xf3 && code[offset+1] == 0x0f &&
			code[offset+2] == 0x1e && (code[offset+3] == 0xfa || code[offset+3] == 0xfb) {
			offset += 4
			addr += 4
			continue
		}

		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			offset++
			addr++
			continue
		}

		switch inst.Op {
		case x86asm.CALL:
			if edge := extractTargetAMD64(inst, addr, CallSiteCall, ConfidenceHigh); edge != nil {
				result = append(result, *edge)
			}
		case x86asm.JMP:
			// x86asm uses distinct Op values for conditional jumps (JNE, JE, JL, etc.),
			// so Op == JMP is always unconditional.
			if edge := extractTargetAMD64(inst, addr, CallSiteJump, ConfidenceMedium); edge != nil {
				result = append(result, *edge)
			}
		}

		offset += inst.Len
		addr += uint64(inst.Len)
	}

	return result, nil
}

// extractTargetAMD64 extracts the call site target from an x86-64 CALL or JMP
// instruction. cfType and baseConfidence are applied to direct (Rel) and absolute
// (Mem without base/index) operands. Register-indirect and RIP-relative operands
// receive adjusted confidence levels.
func extractTargetAMD64(inst x86asm.Inst, sourceAddr uint64, cfType CallSiteType, baseConfidence Confidence) *CallSiteEdge {
	edge := &CallSiteEdge{
		SourceAddr: sourceAddr,
		Type:       cfType,
	}

	switch arg := inst.Args[0].(type) {
	case x86asm.Rel:
		// PC-relative: call/jmp rel32 or rel8
		edge.TargetAddr = sourceAddr + uint64(inst.Len) + uint64(int64(arg))
		edge.AddressMode = AddressingModePCRelative
		edge.Confidence = baseConfidence
		return edge

	case x86asm.Mem:
		if arg.Base == x86asm.RIP && arg.Index == 0 {
			// RIP-relative: call/jmp [rip+disp32]  - dominant indirect form in
			// PIE binaries (PLT/GOT). The referenced memory address is
			// computable: nextPC + disp.
			edge.TargetAddr = sourceAddr + uint64(inst.Len) + uint64(arg.Disp)
			edge.AddressMode = AddressingModePCRelative
			edge.Confidence = ConfidenceMedium
			return edge
		}
		if arg.Base == 0 && arg.Index == 0 {
			// Absolute address: call/jmp [disp]
			edge.TargetAddr = uint64(arg.Disp)
			edge.AddressMode = AddressingModeAbsolute
			edge.Confidence = baseConfidence
			return edge
		}
		// Complex memory addressing (register-based)  - cannot resolve statically
		edge.AddressMode = AddressingModeRegisterIndirect
		edge.Confidence = ConfidenceNone
		return edge

	case x86asm.Reg:
		// Register-indirect: call/jmp rax  - cannot resolve statically
		edge.AddressMode = AddressingModeRegisterIndirect
		edge.Confidence = ConfidenceNone
		return edge

	default:
		return nil
	}
}

func detectCallSitesARM64(code []byte, baseAddr uint64) ([]CallSiteEdge, error) {
	var result []CallSiteEdge

	const insnLen = 4

	for offset := 0; offset+insnLen <= len(code); offset += insnLen {
		inst, err := arm64asm.Decode(code[offset : offset+insnLen])
		if err != nil {
			continue
		}
		addr := baseAddr + uint64(offset)

		switch inst.Op {
		case arm64asm.BL:
			if edge := extractTargetARM64(inst, addr, CallSiteCall, ConfidenceHigh); edge != nil {
				result = append(result, *edge)
			}
		case arm64asm.B:
			// B.cond (conditional branches) carry a Cond argument;
			// they are usually intra-function branches (low confidence).
			// Unconditional B may be a tail call (medium confidence).
			conf := ConfidenceMedium
			for _, arg := range inst.Args {
				if _, ok := arg.(arm64asm.Cond); ok {
					conf = ConfidenceLow
					break
				}
			}
			if edge := extractTargetARM64(inst, addr, CallSiteJump, conf); edge != nil {
				result = append(result, *edge)
			}
		}
	}

	return result, nil
}

// extractTargetARM64 extracts the PC-relative branch target from an ARM64
// BL or B instruction. Returns nil if the first argument is not a PCRel offset.
func extractTargetARM64(inst arm64asm.Inst, sourceAddr uint64, cfType CallSiteType, confidence Confidence) *CallSiteEdge {
	pcrel, ok := inst.Args[0].(arm64asm.PCRel)
	if !ok {
		return nil
	}
	return &CallSiteEdge{
		SourceAddr:  sourceAddr,
		TargetAddr:  sourceAddr + uint64(int64(pcrel)),
		Type:        cfType,
		AddressMode: AddressingModePCRelative,
		Confidence:  confidence,
	}
}
