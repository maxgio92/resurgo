package resurgo_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/maxgio92/resurgo"
)

const (
	demoAppSource = "testdata/demo-app.go"
	demoAppBinary = "demo-app"
)

func TestDetectProloguesAMD64(t *testing.T) {
	// AMD64 instruction encodings:
	// nop                       = 0x90
	// push rbp                  = 0x55
	// mov rbp, rsp              = 0x48 0x89 0xe5
	// sub rsp, 0x20             = 0x48 0x83 0xec 0x20

	tests := []struct {
		name      string
		code      []byte
		baseAddr  uint64
		wantCount int
		wantType  resurgo.PrologueType
		wantAddr  uint64
	}{
		{
			// nop; push rbp; mov rbp, rsp
			// The leading nop ensures push rbp is not at start-of-input,
			// so only the classic pattern fires.
			name:      string(resurgo.PrologueClassic),
			code:      []byte{0x90, 0x55, 0x48, 0x89, 0xe5},
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueClassic,
			wantAddr:  1,
		},
		{
			// sub rsp, 0x20 at start of code (no preceding instruction)
			name:      string(resurgo.PrologueNoFramePointer),
			code:      []byte{0x48, 0x83, 0xec, 0x20},
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueNoFramePointer,
			wantAddr:  0,
		},
		{
			// nop; push rbx (0x53); sub rsp, 0x20 — push not at boundary,
			// only the sub rsp is detected as NoFramePointer.
			name:      "no-frame-pointer-after-push",
			code:      []byte{0x90, 0x53, 0x48, 0x83, 0xec, 0x20},
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueNoFramePointer,
			wantAddr:  2,
		},
		{
			// push rbp; nop — push rbp at start, not followed by mov rbp, rsp
			name:      string(resurgo.ProloguePushOnly),
			code:      []byte{0x55, 0x90},
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.ProloguePushOnly,
			wantAddr:  0,
		},
		{
			name:      "EmptyNil",
			code:      nil,
			wantCount: 0,
		},
		{
			name:      "EmptySlice",
			code:      []byte{},
			wantCount: 0,
		},
		{
			// Garbage bytes that should not match any prologue pattern.
			name:      "InvalidBytes",
			code:      []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prologues, err := resurgo.DetectPrologues(tt.code, tt.baseAddr, resurgo.ArchAMD64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(prologues) != tt.wantCount {
				t.Fatalf("expected %d prologue(s), got %d: %+v", tt.wantCount, len(prologues), prologues)
			}
			if tt.wantCount == 0 {
				return
			}
			if prologues[0].Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, prologues[0].Type)
			}
			if prologues[0].Address != tt.wantAddr {
				t.Errorf("expected address 0x%x, got 0x%x", tt.wantAddr, prologues[0].Address)
			}
		})
	}
}

func TestDetectProloguesARM64(t *testing.T) {
	// ARM64 instruction encodings (little-endian):
	// stp x29, x30, [sp, #-16]! = 0xa9bf7bfd
	// mov x29, sp               = 0x910003fd
	// sub sp, sp, #0x20         = 0xd10083ff
	// nop                       = 0xd503201f
	// ret                       = 0xd65f03c0

	stpX29X30 := uint32(0xa9bf7bfd) // stp x29, x30, [sp, #-16]!
	movX29SP := uint32(0x910003fd)  // mov x29, sp
	subSP := uint32(0xd10083ff)     // sub sp, sp, #0x20
	strX30 := uint32(0xf81e0ffe)    // str x30, [sp, #-32]!
	nop := uint32(0xd503201f)       // nop

	tests := []struct {
		name      string
		code      []byte
		baseAddr  uint64
		wantCount int
		wantType  resurgo.PrologueType
		wantAddr  uint64
	}{
		{
			name:      string(resurgo.PrologueSTPFramePair),
			code:      arm64Insn(stpX29X30, movX29SP),
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueSTPFramePair,
			wantAddr:  0,
		},
		{
			name:      string(resurgo.PrologueSTRLRPreIndex),
			code:      arm64Insn(strX30),
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueSTRLRPreIndex,
			wantAddr:  0,
		},
		{
			name:      string(resurgo.PrologueSubSP),
			code:      arm64Insn(subSP),
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueSubSP,
			wantAddr:  0,
		},
		{
			// stp x29, x30, [sp, #-16]! followed by nop (not mov x29, sp)
			name:      string(resurgo.PrologueSTPOnly),
			code:      arm64Insn(stpX29X30, nop),
			baseAddr:  0,
			wantCount: 1,
			wantType:  resurgo.PrologueSTPOnly,
			wantAddr:  0,
		},
		{
			name:      "ARM64_EmptyNil",
			code:      nil,
			wantCount: 0,
		},
		{
			name:      "ARM64_EmptySlice",
			code:      []byte{},
			wantCount: 0,
		},
		{
			name:      "ARM64_InvalidBytes",
			code:      []byte{0xde, 0xad, 0xbe, 0xef},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prologues, err := resurgo.DetectPrologues(tt.code, tt.baseAddr, resurgo.ArchARM64)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(prologues) != tt.wantCount {
				t.Fatalf("expected %d prologue(s), got %d: %+v", tt.wantCount, len(prologues), prologues)
			}
			if tt.wantCount == 0 {
				return
			}
			if prologues[0].Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, prologues[0].Type)
			}
			if prologues[0].Address != tt.wantAddr {
				t.Errorf("expected address 0x%x, got 0x%x", tt.wantAddr, prologues[0].Address)
			}
		})
	}
}

func TestDetectPrologues_UnsupportedArch(t *testing.T) {
	_, err := resurgo.DetectPrologues([]byte{0x00}, 0, resurgo.Arch("mips"))
	if err == nil {
		t.Fatal("expected error for unsupported architecture, got nil")
	}
}

func TestDetectProloguesFromELF_Go(t *testing.T) {
	tests := []struct {
		name      string
		goarch    string
		buildArgs []string
		minCounts map[resurgo.PrologueType]int
	}{
		{
			name:      "amd64/optimized",
			goarch:    "amd64",
			buildArgs: nil,
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueClassic:        1,
				resurgo.PrologueNoFramePointer: 1,
			},
		},
		{
			name:      "amd64/unoptimized",
			goarch:    "amd64",
			buildArgs: []string{"-gcflags=all=-N -l"},
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueClassic: 1,
			},
		},
		{
			name:      "arm64/optimized",
			goarch:    "arm64",
			buildArgs: nil,
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueSTRLRPreIndex: 1,
			},
		},
		{
			name:      "arm64/unoptimized",
			goarch:    "arm64",
			buildArgs: []string{"-gcflags=all=-N -l"},
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueSTRLRPreIndex: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binPath := filepath.Join(t.TempDir(), demoAppBinary)
			args := append([]string{"build", "-o", binPath}, tt.buildArgs...)
			args = append(args, demoAppSource)

			cmd := exec.Command("go", args...)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+tt.goarch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to compile demo-app: %v\n%s", err, out)
			}

			f, err := os.Open(binPath)
			if err != nil {
				t.Fatalf("failed to open compiled binary: %v", err)
			}
			defer f.Close()

			prologues, err := resurgo.DetectProloguesFromELF(f)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(prologues) == 0 {
				t.Fatal("expected at least one prologue, got none")
			}

			counts := make(map[resurgo.PrologueType]int)
			for _, p := range prologues {
				counts[p.Type]++
			}
			t.Logf("total prologues: %d, by type: %v", len(prologues), counts)

			for typ, min := range tt.minCounts {
				if counts[typ] < min {
					t.Errorf("expected at least %d %s prologue(s), got %d", min, typ, counts[typ])
				}
			}
		})
	}
}

func TestDetectProloguesFromELF_C(t *testing.T) {
	const cSource = "testdata/demo-app.c"

	tests := []struct {
		name      string
		compiler  string
		args      []string
		minCounts map[resurgo.PrologueType]int
	}{
		{
			name:     "amd64/gcc/optimized",
			compiler: "gcc",
			args:     []string{"-O2"},
		},
		{
			name:     "amd64/gcc/unoptimized",
			compiler: "gcc",
			args:     []string{"-O0", "-fno-omit-frame-pointer"},
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueClassic: 1,
			},
		},
		{
			name:     "arm64/clang/optimized",
			compiler: "clang",
			args:     []string{"--target=aarch64-linux-gnu", "-c", "-O2"},
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueSTPFramePair: 1,
			},
		},
		{
			name:     "arm64/clang/unoptimized",
			compiler: "clang",
			args:     []string{"--target=aarch64-linux-gnu", "-c", "-O0"},
			minCounts: map[resurgo.PrologueType]int{
				resurgo.PrologueSubSP: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minCounts := tt.minCounts
			if tt.name == "amd64/gcc/optimized" {
				minCounts = gccOptimizedExpectations(t)
			}
			prologues := compileAndDetect(t, tt.compiler, tt.args, cSource)
			assertPrologues(t, prologues, minCounts)
		})
	}
}

func TestDetectProloguesFromELF_InvalidReader(t *testing.T) {
	r := bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03})
	_, err := resurgo.DetectProloguesFromELF(r)
	if err == nil {
		t.Fatal("expected error for invalid ELF data, got nil")
	}
}

// arm64Insn encodes ARM64 instructions as little-endian bytes.
func arm64Insn(insns ...uint32) []byte {
	buf := make([]byte, 4*len(insns))
	for i, insn := range insns {
		binary.LittleEndian.PutUint32(buf[i*4:], insn)
	}
	return buf
}

// gccMajorVersion returns the major version of the GCC compiler at the given
// path, or 0 if it cannot be determined.
func gccMajorVersion(compiler string) int {
	out, err := exec.Command(compiler, "-dumpversion").Output()
	if err != nil {
		return 0
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), ".", 2)
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return v
}

// gccOptimizedExpectations returns the expected prologue types for GCC -O2
// output based on the installed GCC version.
//
// GCC version determines which prologue patterns are generated when frame
// pointers are omitted (-O2 default):
//
//   - GCC >= 15: emits push rbp (callee-saved) followed by interleaved movs
//     before sub rsp; the push rbp at the function boundary is detected as
//     PushOnly.
//   - GCC 13-14: emits endbr64 (CET) followed immediately by push rbx;
//     sub rsp, which is detected as NoFramePointer after the ENDBR skip
//     and relaxed boundary check.
func gccOptimizedExpectations(t *testing.T) map[resurgo.PrologueType]int {
	t.Helper()
	v := gccMajorVersion("gcc")
	switch {
	case v >= 15:
		return map[resurgo.PrologueType]int{
			resurgo.ProloguePushOnly: 1,
		}
	case v >= 13:
		return map[resurgo.PrologueType]int{
			resurgo.ProloguePushOnly: 1,
		}
	default:
		t.Logf("gcc %d: no version-specific prologue expectation", v)
		return map[resurgo.PrologueType]int{}
	}
}

// compileAndDetect compiles cSource with the given compiler and flags, runs
// prologue detection on the result, and returns the detected prologues.
func compileAndDetect(t *testing.T, compiler string, args []string, cSource string) []resurgo.Prologue {
	t.Helper()
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("%s not found, skipping", compiler)
	}

	outPath := filepath.Join(t.TempDir(), "demo-app-c")
	buildArgs := append(args, "-o", outPath, cSource)

	cmd := exec.Command(compiler, buildArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile %s: %v\n%s", cSource, err, out)
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("failed to open compiled binary: %v", err)
	}
	defer f.Close()

	prologues, err := resurgo.DetectProloguesFromELF(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return prologues
}

// assertPrologues verifies that prologues is non-empty and that the
// per-type counts meet the specified minimums.
func assertPrologues(t *testing.T, prologues []resurgo.Prologue, minCounts map[resurgo.PrologueType]int) {
	t.Helper()
	if len(prologues) == 0 {
		t.Fatal("expected at least one prologue, got none")
	}

	counts := make(map[resurgo.PrologueType]int)
	for _, p := range prologues {
		counts[p.Type]++
	}
	t.Logf("total prologues: %d, by type: %v", len(prologues), counts)

	for typ, count := range minCounts {
		if counts[typ] < count {
			t.Errorf("expected at least %d %s prologue(s), got %d", count, typ, counts[typ])
		}
	}
}
