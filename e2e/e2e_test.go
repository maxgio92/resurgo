//go:build e2e

package e2e_test

import (
	"debug/elf"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/maxgio92/resurgo"
)

// detectionStats holds precision/recall metrics for a single detection run.
type detectionStats struct {
	// Total user functions expected.
	total int
	// True positives: user functions found at medium-or-higher confidence.
	truePositives int
	// False positives: candidates whose VA does not match any user function.
	falsePositives int
	// missed returns the number of user functions not detected.
	missed []string
}

func (s detectionStats) tpRate() float64 {
	if s.total == 0 {
		return 0
	}
	return float64(s.truePositives) / float64(s.total) * 100
}

func (s detectionStats) missedRate() float64 {
	return 100 - s.tpRate()
}

// fpMultiplier returns the ratio of false positives to the total number of
// real user functions (ground truth), regardless of how many were detected.
// This measures noise relative to the true function population, not just the
// subset the detector happened to find.
// Returns +Inf when there are false positives but no real functions at all.
func (s detectionStats) fpMultiplier() float64 {
	if s.total == 0 {
		if s.falsePositives > 0 {
			return math.Inf(1)
		}
		return 0
	}
	return float64(s.falsePositives) / float64(s.total)
}

// logSummary writes a structured summary to t.Log so CI output is self-
// explanatory without needing to read individual sub-test lines.
func (s detectionStats) logSummary(t *testing.T) {
	t.Helper()
	t.Logf("true_positives:   %d/%d (%.0f%%)",
		s.truePositives, s.total, s.tpRate())
	t.Logf("missed:           %d/%d (%.0f%%) %v",
		len(s.missed), s.total, s.missedRate(), s.missed)
	if math.IsInf(s.fpMultiplier(), 1) {
		t.Logf("false_positives:  %d (+Inf multiplier - no real functions in ground truth)",
			s.falsePositives)
	} else {
		t.Logf("false_positives:  %d (%.2fx per real function)",
			s.falsePositives, s.fpMultiplier())
	}
}

// compileCBinary compiles src with compiler and cflags, writing the output to
// out. Skips the test if compiler is not found in PATH.
func compileCBinary(t *testing.T, compiler string, cflags []string, src, out string) {
	t.Helper()
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("%s not found in PATH, skipping", compiler)
	}
	args := append(append([]string{}, cflags...), "-o", out, src)
	cmd := exec.Command(compiler, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, output)
	}
}

// stripSymbolTable strips the symbol table from src using the given strip
// tool, writing the result to dst. Skips the test if the tool is not in PATH.
func stripSymbolTable(t *testing.T, stripTool, src, dst string) {
	t.Helper()
	if _, err := exec.LookPath(stripTool); err != nil {
		t.Skipf("%s not found in PATH, skipping", stripTool)
	}
	cmd := exec.Command(stripTool, "--strip-all", "-o", dst, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strip failed: %v\n%s", err, out)
	}
}

// groundTruthVAs reads the ELF symbol table from binPath and returns a map of
// name -> virtual address for each name in wantNames.
func groundTruthVAs(t *testing.T, binPath string, wantNames []string) map[string]uint64 {
	t.Helper()
	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatalf("elf.Open(%s): %v", binPath, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("f.Symbols: %v", err)
	}

	wanted := make(map[string]struct{}, len(wantNames))
	for _, name := range wantNames {
		wanted[name] = struct{}{}
	}

	result := make(map[string]uint64)
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		if _, ok := wanted[sym.Name]; ok {
			result[sym.Name] = sym.Value
		}
	}
	return result
}

// allFunctionVAs reads the ELF symbol table from binPath and returns the
// virtual address of every STT_FUNC symbol, regardless of name. Used to
// distinguish genuine false positives (addresses the detector reports that are
// not real function entries) from CRT boilerplate that the detector correctly
// finds but that are outside the user-defined recall target.
func allFunctionVAs(t *testing.T, binPath string) map[uint64]struct{} {
	t.Helper()
	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatalf("elf.Open(%s): %v", binPath, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("f.Symbols: %v", err)
	}

	result := make(map[uint64]struct{})
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			result[sym.Value] = struct{}{}
		}
	}
	return result
}

// measure compiles src, strips it, runs DetectFunctionsFromELF, and returns
// per-function detection details alongside aggregated detectionStats.
// stripTool is the strip binary to use (e.g. "strip" for the host arch,
// "aarch64-linux-gnu-strip" for cross-compiled ARM64 binaries).
func measure(
	t *testing.T,
	compiler string,
	stripTool string,
	cflags []string,
	src string,
	userFuncs []string,
) (byVA map[uint64]resurgo.FunctionCandidate, truth map[string]uint64, stats detectionStats) {
	t.Helper()

	dir := t.TempDir()
	unstripped := filepath.Join(dir, "binary")
	stripped := filepath.Join(dir, "binary-stripped")

	compileCBinary(t, compiler, cflags, src, unstripped)
	stripSymbolTable(t, stripTool, unstripped, stripped)

	truth = groundTruthVAs(t, unstripped, userFuncs)
	if len(truth) < len(userFuncs) {
		missing := make([]string, 0)
		for _, name := range userFuncs {
			if _, ok := truth[name]; !ok {
				missing = append(missing, name)
			}
		}
		t.Fatalf("ground truth missing functions: %v", missing)
	}

	f, err := os.Open(stripped)
	if err != nil {
		t.Fatalf("os.Open: %v", err)
	}
	defer f.Close()

	candidates, err := resurgo.DetectFunctionsFromELF(f)
	if err != nil {
		t.Fatalf("DetectFunctionsFromELF: %v", err)
	}

	byVA = make(map[uint64]resurgo.FunctionCandidate, len(candidates))
	for _, c := range candidates {
		byVA[c.Address] = c
	}

	// allFuncs covers every STT_FUNC symbol in the unstripped binary,
	// including CRT boilerplate. A candidate is a true false positive only
	// if its address does not correspond to any real function entry —
	// finding _start or frame_dummy is correct behaviour, not noise.
	allFuncs := allFunctionVAs(t, unstripped)

	// Build stats.
	// TP/recall: measured against userFuncs only (the caller's target set).
	// FP: measured against allFuncs so that CRT detections are not penalised.
	stats.total = len(userFuncs)
	for _, name := range userFuncs {
		if _, ok := byVA[truth[name]]; ok {
			stats.truePositives++
		} else {
			stats.missed = append(stats.missed, name)
		}
	}
	for va := range byVA {
		if _, ok := allFuncs[va]; !ok {
			stats.falsePositives++
		}
	}

	// Log per-function breakdown.
	names := make([]string, 0, len(truth))
	for name := range truth {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		va := truth[name]
		if c, ok := byVA[va]; ok {
			t.Logf("  %-12s VA=0x%x  %s  %s", name, va, c.DetectionType, c.Confidence)
		} else {
			t.Logf("  %-12s VA=0x%x  NOT DETECTED", name, va)
		}
	}

	return byVA, truth, stats
}

// TestDetectFunctionsFromELF_StrippedC_Unoptimized verifies that
// DetectFunctionsFromELF finds all user-defined functions in a stripped C
// binary compiled without optimisation.
//
// Expected: 100% true-positive rate; false positives present at roughly 1x
// (CRT scaffolding and PLT stubs); observe() at high confidence due to its
// high call-site density.
func TestDetectFunctionsFromELF_StrippedC_Unoptimized(t *testing.T) {
	userFuncs := []string{"observe", "add", "multiply", "subtract", "divide", "main"}

	byVA, truth, stats := measure(
		t, "gcc", "strip", []string{"-O0", "-fno-inline"},
		"../testdata/demo-app.c", userFuncs,
	)
	stats.logSummary(t)

	// Full recall is required for the unoptimized case.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier should stay below 0.5x. PLT stubs are filtered and
	// CRT functions are excluded from the FP count (they are real
	// detections); only genuinely spurious addresses remain.
	if stats.fpMultiplier() >= 0.5 {
		t.Errorf("false positive multiplier %.2fx >= 0.50x: detector is too noisy",
			stats.fpMultiplier())
	}

	// observe() is called from four functions (twice each) and must reach
	// high confidence.
	va := truth["observe"]
	if c, ok := byVA[va]; !ok {
		t.Errorf("observe(0x%x): not detected", va)
	} else if c.Confidence != resurgo.ConfidenceHigh {
		t.Errorf("observe(0x%x): confidence=%s, want high", va, c.Confidence)
	}
}

// TestDetectFunctionsFromELF_StrippedC_Optimized documents the known
// limitation of DetectFunctionsFromELF on optimized stripped C binaries.
//
// Source: testdata/stripped-app.c - plain C without anti-inlining attributes.
// Under -O2, add/mul are inlined into their callers and factorial's tail call
// is converted to a loop: all three lose both their prologue and their call-
// site edges, making them undetectable. Only fib (doubly recursive) retains
// enough signal.
//
// This test does not assert full recall. It asserts the minimum that can be
// reliably expected (fib at high confidence) and verifies the stats snapshot
// matches the known limitation so improvements and regressions are visible.
//
// See: https://github.com/maxgio92/resurgo/issues/13
func TestDetectFunctionsFromELF_StrippedC_Optimized(t *testing.T) {
	userFuncs := []string{"add", "mul", "factorial", "fib", "main"}

	byVA, truth, stats := measure(
		t, "gcc", "strip", []string{"-O2"},
		"testdata/stripped-app.c", userFuncs,
	)
	stats.logSummary(t)

	// fib is doubly recursive and must always be detected at high confidence.
	va := truth["fib"]
	if c, ok := byVA[va]; !ok {
		t.Errorf("fib(0x%x): not detected (expected high confidence)", va)
	} else if c.Confidence != resurgo.ConfidenceHigh {
		t.Errorf("fib(0x%x): confidence=%s, want high", va, c.Confidence)
	}

	// Document the known limitation: TP rate may be below 100% due to
	// inlining. If it flips to 100%, issue #13 may be resolved.
	if stats.tpRate() == 100 {
		t.Logf("NOTICE: true positive rate is now 100%% - issue #13 may be resolved; " +
			"consider promoting this test to a full recall assertion")
	}

	// At least one function must be found.
	if stats.truePositives == 0 {
		t.Errorf("true positives: 0/%d - detector found nothing; regression?", stats.total)
	}

	// FP multiplier must stay below 0.5x. PLT stubs are filtered and
	// CRT functions are not counted as FPs; only genuinely spurious
	// addresses remain (~0.2x baseline with gcc 14.2.0).
	if stats.fpMultiplier() >= 0.5 {
		t.Errorf("false positive multiplier %.2fx >= 0.50x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_StrippedC_Optimized_ARM64 validates boundary
// detection on a cross-compiled ARM64 binary and documents its known
// limitations.
//
// The test cross-compiles testdata/stripped-app.c with aarch64-linux-gnu-gcc
// at -O2. On ARM64, gcc packs small leaf functions back-to-back on 4-byte
// boundaries without 16-byte alignment fill: mul (2 instructions) lands at a
// non-16-byte-aligned address and is never called directly from any site in
// the binary (all calls to it were inlined by the compiler). It is therefore
// undetectable by any current strategy (no prologue, no call-site edge, no
// 16-byte boundary).
//
// This test does not assert full recall. It asserts the minimum that can be
// reliably expected (fib at high confidence) and captures a snapshot so
// improvements and regressions are visible in CI.
//
// Skipped if aarch64-linux-gnu-gcc or aarch64-linux-gnu-strip are not in PATH.
func TestDetectFunctionsFromELF_StrippedC_Optimized_ARM64(t *testing.T) {
	userFuncs := []string{"add", "mul", "factorial", "fib", "main"}

	byVA, truth, stats := measure(
		t, "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-strip",
		[]string{"-O2"},
		"testdata/stripped-app.c", userFuncs,
	)
	stats.logSummary(t)

	// fib is doubly recursive and must always reach high confidence.
	va := truth["fib"]
	if c, ok := byVA[va]; !ok {
		t.Errorf("fib(0x%x): not detected (expected high confidence)", va)
	} else if c.Confidence != resurgo.ConfidenceHigh {
		t.Errorf("fib(0x%x): confidence=%s, want high", va, c.Confidence)
	}

	// Regression guard: at least 4/5 functions must be found.
	if stats.truePositives < 4 {
		t.Errorf("true positives: %d/%d - regression? expected at least 4; missed: %v",
			stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 2x. PLT stubs and CRT boilerplate
	// are excluded; residual FPs are intra-CRT jump targets inside
	// .text that the anchor-range filter does not suppress (~1.6x
	// baseline with gcc 14.2.0 aarch64-linux-gnu).
	if stats.fpMultiplier() >= 2.0 {
		t.Errorf("false positive multiplier %.2fx >= 2.00x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

