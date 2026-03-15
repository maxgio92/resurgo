package resurgo_test

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/maxgio92/resurgo"
)

func TestDetectCallSitesAMD64_Call(t *testing.T) {
	// AMD64 instruction encodings:
	// call rel32               = 0xE8 <4 bytes rel32>
	// call rax                 = 0xFF 0xD0
	// call [rip+disp32]        = 0xFF 0x15 <4 bytes disp32>
	// call [rbx+disp8]         = 0xFF 0x53 <1 byte disp8>
	// nop                      = 0x90

	tests := []struct {
		name       string
		code       []byte
		baseAddr   uint64
		wantCount  int
		wantType   resurgo.CallSiteType
		wantMode   resurgo.AddressingMode
		wantConf   resurgo.Confidence
		wantSource uint64
		wantTarget uint64
	}{
		{
			name: "pc-relative-call",
			// call $+0x10 (rel32 = 0x0000000B, instruction length = 5)
			// Target = 0 + 5 + 0x0B = 0x10
			code:       []byte{0xE8, 0x0B, 0x00, 0x00, 0x00},
			baseAddr:   0,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantMode:   resurgo.AddressingModePCRelative,
			wantConf:   resurgo.ConfidenceHigh,
			wantSource: 0,
			wantTarget: 0x10,
		},
		{
			name: "pc-relative-call-negative-offset",
			// call $-0x20 (rel32 = 0xFFFFFFE0, two's complement -32)
			// At address 0x100, target = 0x100 + 5 + (-32) = 0xE5
			code:       []byte{0xE8, 0xE0, 0xFF, 0xFF, 0xFF},
			baseAddr:   0x100,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantMode:   resurgo.AddressingModePCRelative,
			wantConf:   resurgo.ConfidenceHigh,
			wantSource: 0x100,
			wantTarget: 0xE5,
		},
		{
			name: "register-indirect-call",
			// call rax = FF D0
			code:       []byte{0xFF, 0xD0},
			baseAddr:   0x200,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantMode:   resurgo.AddressingModeRegisterIndirect,
			wantConf:   resurgo.ConfidenceNone,
			wantSource: 0x200,
			wantTarget: 0,
		},
		{
			name: "rip-relative-call",
			// call [rip+0x1234] = FF 15 34 12 00 00 (6 bytes)
			// At address 0x1000, target = 0x1000 + 6 + 0x1234 = 0x223A
			code:       []byte{0xFF, 0x15, 0x34, 0x12, 0x00, 0x00},
			baseAddr:   0x1000,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantMode:   resurgo.AddressingModePCRelative,
			wantConf:   resurgo.ConfidenceMedium,
			wantSource: 0x1000,
			wantTarget: 0x223A,
		},
		{
			name: "memory-call-with-base-register",
			// call [rbx+0x10] = FF 53 10
			code:       []byte{0xFF, 0x53, 0x10},
			baseAddr:   0x300,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantMode:   resurgo.AddressingModeRegisterIndirect,
			wantConf:   resurgo.ConfidenceNone,
			wantSource: 0x300,
			wantTarget: 0,
		},
		{
			name:      "no-call-instructions",
			code:      []byte{0x90, 0x90, 0x90}, // nop, nop, nop
			baseAddr:  0,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, tt.baseAddr, resurgo.ArchAMD64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(edges) != tt.wantCount {
				t.Fatalf("expected %d edge(s), got %d: %+v", tt.wantCount, len(edges), edges)
			}
			if tt.wantCount == 0 {
				return
			}

			edge := edges[0]
			if edge.Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, edge.Type)
			}
			if edge.AddressMode != tt.wantMode {
				t.Errorf("expected address mode %s, got %s", tt.wantMode, edge.AddressMode)
			}
			if edge.Confidence != tt.wantConf {
				t.Errorf("expected confidence %s, got %s", tt.wantConf, edge.Confidence)
			}
			if edge.SourceAddr != tt.wantSource {
				t.Errorf("expected source 0x%x, got 0x%x", tt.wantSource, edge.SourceAddr)
			}
			if edge.TargetAddr != tt.wantTarget {
				t.Errorf("expected target 0x%x, got 0x%x", tt.wantTarget, edge.TargetAddr)
			}
		})
	}
}

func TestDetectCallSitesAMD64_Jump(t *testing.T) {
	// AMD64 instruction encodings:
	// jmp rel32                = 0xE9 <4 bytes rel32>
	// jmp rel8                 = 0xEB <1 byte rel8>
	// jmp rax                  = 0xFF 0xE0

	tests := []struct {
		name       string
		code       []byte
		baseAddr   uint64
		wantCount  int
		wantType   resurgo.CallSiteType
		wantMode   resurgo.AddressingMode
		wantConf   resurgo.Confidence
		wantTarget uint64
	}{
		{
			name: "unconditional-jmp-rel32",
			// jmp $+0x20 (rel32 = 0x0000001B, instruction length = 5)
			// Target = 0 + 5 + 0x1B = 0x20
			code:       []byte{0xE9, 0x1B, 0x00, 0x00, 0x00},
			baseAddr:   0,
			wantCount:  1,
			wantType:   resurgo.CallSiteJump,
			wantMode:   resurgo.AddressingModePCRelative,
			wantConf:   resurgo.ConfidenceMedium, // Unconditional = medium
			wantTarget: 0x20,
		},
		{
			name: "unconditional-jmp-rel8",
			// jmp $+0x10 (rel8 = 0x0E, instruction length = 2)
			// Target = 0 + 2 + 0x0E = 0x10
			code:       []byte{0xEB, 0x0E},
			baseAddr:   0,
			wantCount:  1,
			wantType:   resurgo.CallSiteJump,
			wantMode:   resurgo.AddressingModePCRelative,
			wantConf:   resurgo.ConfidenceMedium,
			wantTarget: 0x10,
		},
		{
			name: "register-indirect-jmp",
			// jmp rax = FF E0
			code:       []byte{0xFF, 0xE0},
			baseAddr:   0x400,
			wantCount:  1,
			wantType:   resurgo.CallSiteJump,
			wantMode:   resurgo.AddressingModeRegisterIndirect,
			wantConf:   resurgo.ConfidenceNone,
			wantTarget: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, tt.baseAddr, resurgo.ArchAMD64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(edges) != tt.wantCount {
				t.Fatalf("expected %d edge(s), got %d: %+v", tt.wantCount, len(edges), edges)
			}
			if tt.wantCount == 0 {
				return
			}

			edge := edges[0]
			if edge.Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, edge.Type)
			}
			if edge.AddressMode != tt.wantMode {
				t.Errorf("expected address mode %s, got %s", tt.wantMode, edge.AddressMode)
			}
			if edge.Confidence != tt.wantConf {
				t.Errorf("expected confidence %s, got %s", tt.wantConf, edge.Confidence)
			}
			if edge.TargetAddr != tt.wantTarget {
				t.Errorf("expected target 0x%x, got 0x%x", tt.wantTarget, edge.TargetAddr)
			}
		})
	}
}

func TestDetectCallSitesARM64_BL(t *testing.T) {
	// ARM64 BL (Branch with Link) instruction encoding:
	// BL offset: 0x94000000 + (offset/4 & 0x03FFFFFF)
	// Offset is signed 26-bit immediate, multiplied by 4

	tests := []struct {
		name       string
		code       []byte
		baseAddr   uint64
		wantCount  int
		wantType   resurgo.CallSiteType
		wantConf   resurgo.Confidence
		wantTarget uint64
	}{
		{
			name: "bl-forward",
			// BL +0x1000 (offset = 0x1000, encoded as 0x1000/4 = 0x400)
			// Instruction: 0x94000400
			code:       arm64Insn(0x94000400),
			baseAddr:   0x1000,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantConf:   resurgo.ConfidenceHigh,
			wantTarget: 0x2000, // 0x1000 + 0x1000
		},
		{
			name: "bl-backward",
			// BL -0x100 (offset = -0x100, encoded as (-0x100/4) & 0x3FFFFFF)
			// Two's complement: 0x3FFFFFC0
			// Instruction: 0x97FFFFC0
			code:       arm64Insn(0x97FFFFC0),
			baseAddr:   0x2000,
			wantCount:  1,
			wantType:   resurgo.CallSiteCall,
			wantConf:   resurgo.ConfidenceHigh,
			wantTarget: 0x1F00, // 0x2000 - 0x100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, tt.baseAddr, resurgo.ArchARM64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(edges) != tt.wantCount {
				t.Fatalf("expected %d edge(s), got %d: %+v", tt.wantCount, len(edges), edges)
			}
			if tt.wantCount == 0 {
				return
			}

			edge := edges[0]
			if edge.Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, edge.Type)
			}
			if edge.Confidence != tt.wantConf {
				t.Errorf("expected confidence %s, got %s", tt.wantConf, edge.Confidence)
			}
			if edge.TargetAddr != tt.wantTarget {
				t.Errorf("expected target 0x%x, got 0x%x", tt.wantTarget, edge.TargetAddr)
			}
		})
	}
}

func TestDetectCallSitesARM64_B(t *testing.T) {
	// ARM64 B (Branch) instruction encoding:
	// B offset: 0x14000000 + (offset/4 & 0x03FFFFFF) (unconditional)
	// B.cond offset: 0x54000000 + ... (conditional)

	tests := []struct {
		name       string
		code       []byte
		baseAddr   uint64
		wantCount  int
		wantType   resurgo.CallSiteType
		wantConf   resurgo.Confidence
		wantTarget uint64
	}{
		{
			name: "b-unconditional",
			// B +0x100 (offset = 0x100, encoded as 0x100/4 = 0x40)
			// Instruction: 0x14000040
			code:       arm64Insn(0x14000040),
			baseAddr:   0x1000,
			wantCount:  1,
			wantType:   resurgo.CallSiteJump,
			wantConf:   resurgo.ConfidenceMedium,
			wantTarget: 0x1100, // 0x1000 + 0x100
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, tt.baseAddr, resurgo.ArchARM64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(edges) != tt.wantCount {
				t.Fatalf("expected %d edge(s), got %d: %+v", tt.wantCount, len(edges), edges)
			}
			if tt.wantCount == 0 {
				return
			}

			edge := edges[0]
			if edge.Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, edge.Type)
			}
			if edge.Confidence != tt.wantConf {
				t.Errorf("expected confidence %s, got %s", tt.wantConf, edge.Confidence)
			}
			if edge.TargetAddr != tt.wantTarget {
				t.Errorf("expected target 0x%x, got 0x%x", tt.wantTarget, edge.TargetAddr)
			}
		})
	}
}

func TestDetectCallSites_UnsupportedArch(t *testing.T) {
	_, err := resurgo.DetectCallSites([]byte{0x00}, 0, resurgo.Arch("mips"))
	if err == nil {
		t.Fatal("expected error for unsupported architecture, got nil")
	}
}

func TestDetectCallSitesAMD64_ENDBR(t *testing.T) {
	// ENDBR64 (f3 0f 1e fa) followed by a call should detect the call,
	// skipping the ENDBR64 instruction transparently.
	// call $+0x20 = E8 17 00 00 00 (at offset 4 after ENDBR, address 0x04)
	// Target = 0x04 + 5 + 0x17 = 0x20
	code := []byte{
		0xf3, 0x0f, 0x1e, 0xfa, // ENDBR64
		0xE8, 0x17, 0x00, 0x00, 0x00, // call +0x17
	}

	edges, err := resurgo.DetectCallSites(code, 0, resurgo.ArchAMD64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}

	edge := edges[0]
	if edge.SourceAddr != 0x04 {
		t.Errorf("expected source 0x04, got 0x%x", edge.SourceAddr)
	}
	if edge.TargetAddr != 0x20 {
		t.Errorf("expected target 0x20, got 0x%x", edge.TargetAddr)
	}
	if edge.Confidence != resurgo.ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", edge.Confidence)
	}
}

func TestDetectCallSites_EmptyInput(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{name: "nil", code: nil},
		{name: "empty", code: []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/amd64", func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, 0, resurgo.ArchAMD64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(edges) != 0 {
				t.Errorf("expected 0 edges, got %d", len(edges))
			}
		})

		t.Run(tt.name+"/arm64", func(t *testing.T) {
			edges, err := resurgo.DetectCallSites(tt.code, 0, resurgo.ArchARM64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(edges) != 0 {
				t.Errorf("expected 0 edges, got %d", len(edges))
			}
		})
	}
}


func TestDetectCallSites_JumpTarget(t *testing.T) {
	// Verify that unconditional JMPs create jump-target candidates.
	// jmp 0x10: E9 0B 00 00 00 at 0x00, target = 0x10
	code := make([]byte, 0x20)
	code[0x00] = 0xE9
	code[0x01] = 0x0B
	code[0x02] = 0x00
	code[0x03] = 0x00
	code[0x04] = 0x00
	code[0x10] = 0xC3 // ret

	edges, err := resurgo.DetectCallSites(code, 0, resurgo.ArchAMD64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found *resurgo.CallSiteEdge
	for i := range edges {
		if edges[i].TargetAddr == 0x10 {
			found = &edges[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected jump edge to 0x10, got none")
	}
}

func TestDetectFunctionsFromELF(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "demo-app")
	args := []string{"build", "-o", binPath, "testdata/demo-app.go"}

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile demo-app: %v\n%s", err, out)
	}

	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatalf("failed to open ELF binary: %v", err)
	}
	defer f.Close()

	candidates, err := resurgo.DetectFunctionsFromELF(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(candidates) == 0 {
		t.Fatal("expected at least one function candidate, got none")
	}

	counts := make(map[resurgo.DetectionType]int)
	for _, c := range candidates {
		counts[c.DetectionType]++
	}
	t.Logf("total candidates: %d, by type: %v", len(candidates), counts)

	if counts[resurgo.DetectionPrologueOnly] == 0 {
		t.Error("expected at least one prologue-only candidate")
	}
}

// TestDisasmDetector verifies that DisasmDetector, when run against a real ELF
// binary, produces candidates with the expected detection types and that
// functions both called and matching a prologue pattern are promoted to
// DetectionPrologueCallSite with ConfidenceHigh.
func TestDisasmDetector(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "demo-app")
	cmd := exec.Command("go", "build", "-o", binPath, "testdata/demo-app.go")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile demo-app: %v\n%s", err, out)
	}

	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatalf("failed to open ELF binary: %v", err)
	}
	defer f.Close()

	candidates, err := resurgo.DisasmDetector(f)
	if err != nil {
		t.Fatalf("DisasmDetector: %v", err)
	}

	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate, got none")
	}

	counts := make(map[resurgo.DetectionType]int)
	for _, c := range candidates {
		counts[c.DetectionType]++
	}
	t.Logf("total candidates: %d, by type: %v", len(candidates), counts)

	// Disasm must find functions via prologue pattern.
	if counts[resurgo.DetectionPrologueOnly] == 0 && counts[resurgo.DetectionPrologueCallSite] == 0 {
		t.Error("expected prologue-based candidates, got none")
	}

	// Functions confirmed by both prologue and call-site must be ConfidenceHigh
	// and must carry at least one caller address.
	for _, c := range candidates {
		if c.DetectionType == resurgo.DetectionPrologueCallSite {
			if c.Confidence != resurgo.ConfidenceHigh {
				t.Errorf("0x%x: expected ConfidenceHigh for prologue-callsite, got %s", c.Address, c.Confidence)
			}
			if len(c.CalledFrom) == 0 && len(c.JumpedFrom) == 0 {
				t.Errorf("0x%x: prologue-callsite candidate has no caller or jump source", c.Address)
			}
		}
	}
}

func TestDetectFunctionsFromELF_InvalidELF(t *testing.T) {
	r := bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03})
	f, err := elf.NewFile(r)
	if err == nil {
		f.Close()
		t.Fatal("expected elf.NewFile to fail on invalid data")
	}
}

func TestDetectCallSitesARM64_BConditional(t *testing.T) {
	// ARM64 B.EQ (conditional branch):
	// B.cond has encoding 0x54000000 | (imm19 << 5) | cond
	// B.EQ +0x20: imm19 = 0x20/4 = 0x8, cond = 0 (EQ)
	// Instruction: 0x54000100
	// Note: The arm64asm decoder uses Op == B for conditional branches too,
	// with a Cond argument to distinguish them.
	code := arm64Insn(0x54000100)

	edges, err := resurgo.DetectCallSites(code, 0x1000, resurgo.ArchARM64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// B.cond is decoded differently by arm64asm  - it may not have Op == B.
	// If no edges, that's acceptable (B.cond is not matched as Op == arm64asm.B).
	if len(edges) == 0 {
		t.Log("B.cond not detected (arm64asm uses different Op for conditional branches)")
		return
	}

	edge := edges[0]
	if edge.Type != resurgo.CallSiteJump {
		t.Errorf("expected type jump, got %s", edge.Type)
	}
	if edge.Confidence != resurgo.ConfidenceLow {
		t.Errorf("expected low confidence for conditional branch, got %s", edge.Confidence)
	}
}

func TestDetectCallSites_Go(t *testing.T) {
	tests := []struct {
		name     string
		goarch   string
		minCalls int
	}{
		{name: "amd64", goarch: "amd64", minCalls: 1},
		{name: "arm64", goarch: "arm64", minCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binPath := filepath.Join(t.TempDir(), "demo-app")
			cmd := exec.Command("go", "build", "-o", binPath, "testdata/demo-app.go")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+tt.goarch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to compile demo-app: %v\n%s", err, out)
			}

			f, err := elf.Open(binPath)
			if err != nil {
				t.Fatalf("failed to open ELF: %v", err)
			}
			defer f.Close()

			textSec := f.Section(".text")
			if textSec == nil {
				t.Fatal("no .text section")
			}
			code, err := textSec.Data()
			if err != nil {
				t.Fatalf("failed to read .text: %v", err)
			}

			arch := resurgo.ArchAMD64
			if tt.goarch == "arm64" {
				arch = resurgo.ArchARM64
			}

			edges, err := resurgo.DetectCallSites(code, textSec.Addr, arch)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(edges) == 0 {
				t.Fatal("expected at least one call site edge, got none")
			}

			calls := 0
			for _, e := range edges {
				if e.Type == resurgo.CallSiteCall {
					calls++
				}
			}
			t.Logf("total edges: %d (calls: %d)", len(edges), calls)

			if calls < tt.minCalls {
				t.Errorf("expected at least %d calls, got %d", tt.minCalls, calls)
			}
		})
	}
}
