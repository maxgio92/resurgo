package resurgo_test

import (
	"encoding/binary"
	"testing"

	"github.com/maxgio92/resurgo"
)

// encodeCallRel32 writes an AMD64 CALL rel32 instruction at code[offset:].
func encodeCallRel32(code []byte, offset int, baseAddr, target uint64) {
	source := baseAddr + uint64(offset)
	rel := int32(int64(target) - int64(source+5))
	code[offset] = 0xE8
	binary.LittleEndian.PutUint32(code[offset+1:], uint32(rel))
}

// encodeJmpRel32 writes an AMD64 JMP rel32 instruction at code[offset:].
func encodeJmpRel32(code []byte, offset int, baseAddr, target uint64) {
	source := baseAddr + uint64(offset)
	rel := int32(int64(target) - int64(source+5))
	code[offset] = 0xE9
	binary.LittleEndian.PutUint32(code[offset+1:], uint32(rel))
}

// arm64BranchInsn encodes an ARM64 BL or B instruction word.
// opBase is 0x94000000 for BL or 0x14000000 for B.
func arm64BranchInsn(opBase uint32, source, target uint64) uint32 {
	off := int64(target) - int64(source)
	imm26 := uint32(off/4) & 0x03FFFFFF
	return opBase | imm26
}

// assertConvergence checks convergence between prologue and call-site detection
// by running both independently and counting addresses found by both signals.
// minTotal is the minimum number of candidates expected, minBoth the minimum
// number of addresses confirmed by both signals, and minRatio the minimum
// convergence ratio (both / total).
func assertConvergence(t *testing.T, code []byte, baseAddr uint64, arch resurgo.Arch, minTotal, minBoth int, minRatio float64) {
	t.Helper()

	prologues, err := resurgo.DetectPrologues(code, baseAddr, arch)
	if err != nil {
		t.Fatalf("DetectPrologues: %v", err)
	}
	edges, err := resurgo.DetectCallSites(code, baseAddr, arch)
	if err != nil {
		t.Fatalf("DetectCallSites: %v", err)
	}

	prologueSet := make(map[uint64]resurgo.PrologueType, len(prologues))
	for _, p := range prologues {
		prologueSet[p.Address] = p.Type
	}
	callSet := make(map[uint64]struct{}, len(edges))
	for _, e := range edges {
		callSet[e.TargetAddr] = struct{}{}
	}

	allAddrs := make(map[uint64]struct{})
	for _, p := range prologues {
		allAddrs[p.Address] = struct{}{}
	}
	for _, e := range edges {
		allAddrs[e.TargetAddr] = struct{}{}
	}

	var bothCount, prologueOnly, callTarget int
	for addr := range allAddrs {
		_, hasPrologue := prologueSet[addr]
		_, hasCall := callSet[addr]
		switch {
		case hasPrologue && hasCall:
			bothCount++
			t.Logf("  0x%x: %-15s (prologue: %s)", addr, resurgo.DetectionPrologueCallSite, prologueSet[addr])
		case hasPrologue:
			prologueOnly++
			t.Logf("  0x%x: %-15s (prologue: %s)", addr, resurgo.DetectionPrologueOnly, prologueSet[addr])
		case hasCall:
			callTarget++
			t.Logf("  0x%x: %-15s", addr, resurgo.DetectionCallTarget)
		}
	}

	total := len(allAddrs)
	ratio := float64(bothCount) / float64(total)

	t.Logf("total=%d both=%d prologue-only=%d call-target=%d ratio=%.3f",
		total, bothCount, prologueOnly, callTarget, ratio)

	if total < minTotal {
		t.Errorf("expected >= %d candidates, got %d", minTotal, total)
	}
	if bothCount < minBoth {
		t.Errorf("expected >= %d 'both' candidates, got %d", minBoth, bothCount)
	}
	if ratio < minRatio {
		t.Errorf("convergence ratio %.3f < %.3f", ratio, minRatio)
	}
	if prologueOnly < 1 {
		t.Error("expected at least one prologue-only candidate")
	}
	if callTarget < 1 {
		t.Error("expected at least one call-target candidate")
	}
}

// buildSyntheticAMD64 builds a synthetic AMD64 .text section with 12 functions
// exercising multiple prologue styles and a realistic call graph.
//
// Layout: 0x300 bytes, base 0x1000, 0x40-byte slots, NOP-filled.
func buildSyntheticAMD64() (code []byte, baseAddr uint64) {
	const base = uint64(0x1000)
	code = make([]byte, 0x300)
	for i := range code {
		code[i] = 0x90 // NOP fill
	}

	// Function offsets (0x40-byte slots)
	const (
		offMain  = 0x000
		offFuncA = 0x040
		offFuncB = 0x080
		offFuncC = 0x0C0
		offFuncD = 0x100
		offFuncE = 0x140
		offFuncF = 0x180
		offFuncG = 0x1C0
		offFuncH = 0x200
		offFuncI = 0x240
		offFuncJ = 0x280
		offFuncK = 0x2C0
	)

	// Classic prologue: push rbp; mov rbp, rsp
	classicPrologue := func(off int) {
		code[off] = 0x55   // push rbp
		code[off+1] = 0x48 // REX.W prefix ┐
		code[off+2] = 0x89 // mov r/m64    ├ mov rbp, rsp
		code[off+3] = 0xe5 // ModRM        ┘
	}

	// main: classic prologue, calls funcA, funcB, funcC
	classicPrologue(offMain)
	encodeCallRel32(code, offMain+4, base, base+uint64(offFuncA))
	encodeCallRel32(code, offMain+9, base, base+uint64(offFuncB))
	encodeCallRel32(code, offMain+14, base, base+uint64(offFuncC))
	code[offMain+19] = 0xC3 // ret

	// funcA: classic prologue, calls funcD, funcE, funcI
	classicPrologue(offFuncA)
	encodeCallRel32(code, offFuncA+4, base, base+uint64(offFuncD))
	encodeCallRel32(code, offFuncA+9, base, base+uint64(offFuncE))
	encodeCallRel32(code, offFuncA+14, base, base+uint64(offFuncI))
	code[offFuncA+19] = 0xC3 // ret

	// funcB: classic prologue, calls funcE, funcF
	classicPrologue(offFuncB)
	encodeCallRel32(code, offFuncB+4, base, base+uint64(offFuncE))
	encodeCallRel32(code, offFuncB+9, base, base+uint64(offFuncF))
	code[offFuncB+14] = 0xC3 // ret

	// funcC: classic prologue, call funcJ, jmp funcK (tail call)
	classicPrologue(offFuncC)
	encodeCallRel32(code, offFuncC+4, base, base+uint64(offFuncJ))
	encodeJmpRel32(code, offFuncC+9, base, base+uint64(offFuncK))

	// funcD: classic prologue
	classicPrologue(offFuncD)
	code[offFuncD+4] = 0xC3 // ret

	// funcE: classic prologue
	classicPrologue(offFuncE)
	code[offFuncE+4] = 0xC3 // ret

	// funcF: classic prologue, jmp funcG (tail call)
	classicPrologue(offFuncF)
	encodeJmpRel32(code, offFuncF+4, base, base+uint64(offFuncG))

	// funcG: classic prologue
	classicPrologue(offFuncG)
	code[offFuncG+4] = 0xC3 // ret

	// funcH: push-only prologue (push rbx at RET boundary)
	code[offFuncH-1] = 0xC3 // ret (boundary marker)
	code[offFuncH] = 0x53   // push rbx (callee-saved)
	code[offFuncH+1] = 0xC3 // ret

	// funcI: no prologue (call-target only)
	code[offFuncI] = 0xC3 // ret

	// funcJ: no-frame-pointer prologue (sub rsp, imm at RET boundary)
	code[offFuncJ-1] = 0xC3 // ret (boundary marker)
	code[offFuncJ] = 0x48   // REX.W prefix ┐
	code[offFuncJ+1] = 0x83 // sub r/m64    ├ sub rsp, 0x20
	code[offFuncJ+2] = 0xec // ModRM: rsp   │
	code[offFuncJ+3] = 0x20 // imm8: 0x20   ┘
	code[offFuncJ+4] = 0xC3 // ret

	// funcK: no prologue (jump-target only)
	code[offFuncK] = 0xC3 // ret

	return code, base
}

// buildSyntheticARM64 builds a synthetic ARM64 .text section with 12 functions
// exercising multiple prologue styles and a realistic call graph.
//
// Layout: 0x300 bytes, base 0x10000, 0x40-byte slots, NOP-filled.
func buildSyntheticARM64() (code []byte, baseAddr uint64) {
	const base = uint64(0x10000)
	code = make([]byte, 0x300)
	// Fill with ARM64 NOPs (0xd503201f = nop)
	for i := 0; i < len(code); i += 4 {
		binary.LittleEndian.PutUint32(code[i:], 0xd503201f) // nop
	}

	putInsn := func(off int, insn uint32) {
		binary.LittleEndian.PutUint32(code[off:], insn)
	}

	const (
		stpX29X30 = uint32(0xa9bf7bfd) // stp x29, x30, [sp, #-16]!
		movX29SP  = uint32(0x910003fd) // mov x29, sp
		subSPImm  = uint32(0xd10083ff) // sub sp, sp, #0x20
		arm64RET  = uint32(0xd65f03c0) // ret
		blOp      = uint32(0x94000000) // BL base opcode
		bOp       = uint32(0x14000000) // B base opcode
	)

	// Function offsets (0x40-byte slots)
	const (
		offMain  = 0x000
		offFuncA = 0x040
		offFuncB = 0x080
		offFuncC = 0x0C0
		offFuncD = 0x100
		offFuncE = 0x140
		offFuncF = 0x180
		offFuncG = 0x1C0
		offFuncH = 0x200
		offFuncI = 0x240
		offFuncJ = 0x280
		offFuncK = 0x2C0
	)

	// STP frame pair prologue: stp x29, x30, [sp, #-16]!; mov x29, sp
	stpPrologue := func(off int) {
		putInsn(off, stpX29X30)
		putInsn(off+4, movX29SP)
	}

	bl := func(srcOff, dstOff int) uint32 {
		return arm64BranchInsn(blOp, base+uint64(srcOff), base+uint64(dstOff))
	}
	b := func(srcOff, dstOff int) uint32 {
		return arm64BranchInsn(bOp, base+uint64(srcOff), base+uint64(dstOff))
	}

	// main: STP frame pair, BL funcA, BL funcB, BL funcC
	stpPrologue(offMain)
	putInsn(offMain+8, bl(offMain+8, offFuncA))
	putInsn(offMain+12, bl(offMain+12, offFuncB))
	putInsn(offMain+16, bl(offMain+16, offFuncC))
	putInsn(offMain+20, arm64RET)

	// funcA: STP frame pair, BL funcD, BL funcE, BL funcI
	stpPrologue(offFuncA)
	putInsn(offFuncA+8, bl(offFuncA+8, offFuncD))
	putInsn(offFuncA+12, bl(offFuncA+12, offFuncE))
	putInsn(offFuncA+16, bl(offFuncA+16, offFuncI))
	putInsn(offFuncA+20, arm64RET)

	// funcB: STP frame pair, BL funcE, BL funcF
	stpPrologue(offFuncB)
	putInsn(offFuncB+8, bl(offFuncB+8, offFuncE))
	putInsn(offFuncB+12, bl(offFuncB+12, offFuncF))
	putInsn(offFuncB+16, arm64RET)

	// funcC: STP frame pair, BL funcJ, B funcK (tail jump)
	stpPrologue(offFuncC)
	putInsn(offFuncC+8, bl(offFuncC+8, offFuncJ))
	putInsn(offFuncC+12, b(offFuncC+12, offFuncK))

	// funcD: STP frame pair
	stpPrologue(offFuncD)
	putInsn(offFuncD+8, arm64RET)

	// funcE: STP frame pair
	stpPrologue(offFuncE)
	putInsn(offFuncE+8, arm64RET)

	// funcF: STP frame pair, B funcG (tail jump)
	stpPrologue(offFuncF)
	putInsn(offFuncF+8, b(offFuncF+8, offFuncG))

	// funcG: STP-only (stp x29, x30 followed by NOP, not mov x29, sp)
	putInsn(offFuncG, stpX29X30)
	// Next slot (offFuncG+4) already has NOP → STP-only fires
	putInsn(offFuncG+8, arm64RET)

	// funcH: STP frame pair (not called/jumped to)
	stpPrologue(offFuncH)
	putInsn(offFuncH+8, arm64RET)

	// funcI: no prologue (call-target only)
	putInsn(offFuncI, arm64RET)

	// funcJ: sub-sp prologue (needs RET before it)
	putInsn(offFuncJ-4, arm64RET) // boundary marker
	putInsn(offFuncJ, subSPImm)
	putInsn(offFuncJ+4, arm64RET)

	// funcK: no prologue (jump-target only)
	putInsn(offFuncK, arm64RET)

	return code, base
}

func TestDetectFunctionsFromELF_Convergence(t *testing.T) {
	// Call graph (both architectures):
	//   main  → funcA, funcB, funcC    (calls)
	//   funcA → funcD, funcE, funcI    (calls)
	//   funcB → funcE, funcF           (calls)
	//   funcC → funcJ, funcK           (call + tail-jump)
	//   funcF → funcG                  (tail-jump)
	//   funcH                          (prologue only, not called)
	//
	// 12 functions, expected 8 "prologue-callsite" / 12 total = 0.667 convergence.

	t.Run("amd64", func(t *testing.T) {
		code, base := buildSyntheticAMD64()
		assertConvergence(t, code, base, resurgo.ArchAMD64, 10, 7, 0.6)
	})

	t.Run("arm64", func(t *testing.T) {
		code, base := buildSyntheticARM64()
		assertConvergence(t, code, base, resurgo.ArchARM64, 10, 7, 0.6)
	})
}
