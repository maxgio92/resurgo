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

const (
	demoAppSource = "testdata/demo-app.go"
	demoAppBinary = "demo-app"
)

// TestDetectFunctionsFromELF verifies that DetectFunctionsFromELF runs the
// full detector and filter pipeline and produces the expected detection types
// for both Go and C binaries.
func TestDetectFunctionsFromELF(t *testing.T) {
	tests := []struct {
		name      string
		build     func(t *testing.T, dir string) string
		wantTypes []resurgo.DetectionType
	}{{
		name: "go",
		build: func(t *testing.T, dir string) string {
			t.Helper()
			binPath := filepath.Join(dir, demoAppBinary)
			cmd := exec.Command("go", "build", "-o", binPath, demoAppSource)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=amd64")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to compile demo-app: %v\n%s", err, out)
			}
			return binPath
		},
		// Go binaries use .gopclntab instead of .eh_frame; no DetectionCFI expected.
		wantTypes: []resurgo.DetectionType{
			resurgo.DetectionPrologueOnly,
			resurgo.DetectionPrologueCallSite,
		},
	}, {
		name: "c",
		build: func(t *testing.T, dir string) string {
			t.Helper()
			if _, err := exec.LookPath("gcc"); err != nil {
				t.Skip("gcc not found, skipping")
			}
			outPath := filepath.Join(dir, "demo-app-c")
			cmd := exec.Command("gcc", "-O0", "-o", outPath, "testdata/demo-app.c")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to compile demo-app.c: %v\n%s", err, out)
			}
			return outPath
		},
		// C binaries carry .eh_frame FDE records; expect CFI candidates.
		wantTypes: []resurgo.DetectionType{
			resurgo.DetectionCFI,
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binPath := tt.build(t, t.TempDir())

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

			for _, typ := range tt.wantTypes {
				if counts[typ] == 0 {
					t.Errorf("expected at least one %s candidate, got none", typ)
				}
			}
		})
	}
}

// TestWithDetectors verifies that a detector registered via WithDetectors is
// actually invoked by the pipeline.
func TestWithDetectors(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()

	called := false
	fake := func(*elf.File) ([]resurgo.FunctionCandidate, error) {
		called = true
		return nil, nil
	}
	if _, err := resurgo.DetectFunctionsFromELF(f, resurgo.WithDetectors(fake)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("WithDetectors: detector was not called")
	}
}

// TestWithFilters verifies that a filter registered via WithFilters is
// actually invoked by the pipeline.
func TestWithFilters(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	f, err := elf.Open(exe)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()

	called := false
	fakeDetector := func(*elf.File) ([]resurgo.FunctionCandidate, error) {
		return []resurgo.FunctionCandidate{{Address: 0x1000}}, nil
	}
	fakeFilter := func(cs []resurgo.FunctionCandidate, _ *elf.File) ([]resurgo.FunctionCandidate, error) {
		called = true
		return cs, nil
	}
	if _, err := resurgo.DetectFunctionsFromELF(f,
		resurgo.WithDetectors(fakeDetector),
		resurgo.WithFilters(fakeFilter),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("WithFilters: filter was not called")
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

// TestDetectors verifies that each detector, when run against a C ELF binary,
// returns non-empty results that include at least one candidate of the expected
// detection type.
func TestDetectors(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found, skipping")
	}

	outPath := filepath.Join(t.TempDir(), "demo-app-c")
	cmd := exec.Command("gcc", "-O0", "-o", outPath, "testdata/demo-app.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile demo-app.c: %v\n%s", err, out)
	}

	f, err := elf.Open(outPath)
	if err != nil {
		t.Fatalf("failed to open ELF binary: %v", err)
	}
	defer f.Close()

	tests := []struct {
		name     string
		detector resurgo.CandidateDetector
		wantType resurgo.DetectionType
		check    func(t *testing.T, candidates []resurgo.FunctionCandidate)
	}{{
		name:     "disasm",
		detector: resurgo.DisasmDetector,
		wantType: resurgo.DetectionPrologueOnly,
	}, {
		// Verify that functions confirmed by both prologue and call-site signals
		// are merged into DetectionPrologueCallSite with ConfidenceHigh and at
		// least one caller or jump source.
		name:     "disasm/merge",
		detector: resurgo.DisasmDetector,
		wantType: resurgo.DetectionPrologueCallSite,
		check: func(t *testing.T, candidates []resurgo.FunctionCandidate) {
			for _, c := range candidates {
				if c.DetectionType != resurgo.DetectionPrologueCallSite {
					continue
				}
				if c.Confidence != resurgo.ConfidenceHigh {
					t.Errorf("0x%x: expected ConfidenceHigh, got %s", c.Address, c.Confidence)
				}
				if len(c.CalledFrom) == 0 && len(c.JumpedFrom) == 0 {
					t.Errorf("0x%x: no CalledFrom or JumpedFrom", c.Address)
				}
			}
		},
	}, {
		name:     "ehframe",
		detector: resurgo.EhFrameDetector,
		wantType: resurgo.DetectionCFI,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates, err := tt.detector(f)
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if len(candidates) == 0 {
				t.Fatalf("%s: expected at least one candidate, got none", tt.name)
			}
			found := false
			for _, c := range candidates {
				if c.DetectionType == tt.wantType {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: expected at least one %s candidate", tt.name, tt.wantType)
			}
			if tt.check != nil {
				tt.check(t, candidates)
			}
		})
	}
}


