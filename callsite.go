package resurgo

import (
	"debug/elf"
	"fmt"
	"io"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	// Recognized call site instruction types.
	CallSiteCall CallSiteType = "call"
	CallSiteJump CallSiteType = "jump"

	// Recognized addressing modes for call site instructions.
	AddressingModePCRelative       AddressingMode = "pc-relative"
	AddressingModeAbsolute         AddressingMode = "absolute"
	AddressingModeRegisterIndirect AddressingMode = "register-indirect"

	// DetectionCallTarget indicates the candidate was found only as a target
	// of one or more CALL instructions.
	DetectionCallTarget DetectionType = "call-target"

	// DetectionJumpTarget indicates the candidate was found only as a target
	// of one or more JMP instructions.
	DetectionJumpTarget DetectionType = "jump-target"

	// DetectionPrologueCallSite indicates the candidate was confirmed by both
	// prologue matching and call-site analysis.
	DetectionPrologueCallSite DetectionType = "prologue-callsite"
)

// CallSiteType represents the type of call site instruction.
type CallSiteType string

// AddressingMode represents how the target address is specified.
type AddressingMode string

// CallSiteEdge represents a detected call site (call or jump to a function).
type CallSiteEdge struct {
	// SourceAddr is the virtual address of the call or jump instruction.
	SourceAddr uint64 `json:"source_addr"`
	// TargetAddr is the virtual address of the call or jump target.
	TargetAddr uint64 `json:"target_addr"`
	// Type indicates whether this edge was produced by a call or jump
	// instruction.
	Type CallSiteType `json:"type"`
	// AddressMode describes how the target address is encoded in the
	// instruction.
	AddressMode AddressingMode `json:"address_mode"`
	// Confidence is the reliability level of this edge.
	Confidence Confidence `json:"confidence"`
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

func detectCallSitesAMD64(code []byte, baseAddr uint64) ([]CallSiteEdge, error) {
	var result []CallSiteEdge

	offset := 0
	addr := baseAddr

	for offset < len(code) {
		// Skip ENDBR64 / ENDBR32: golang.org/x/arch/x86/x86asm does not
		// recognise these CET instructions. They appear at function entries
		// on binaries compiled with -fcf-protection and are transparent to
		// call site detection.
		if isENDBR(code, offset) {
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
