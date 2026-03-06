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

// TestDetectFunctionsFromELF_StrippedC_Optimized validates that
// DetectFunctionsFromELF correctly identifies all user functions in a
// realistic optimized stripped C binary.
//
// Source: testdata/stripped-app.c - a mixed text/numeric utility with 16
// functions covering a range of shapes: loop-heavy leaves, multi-caller
// aggregators, a nested-loop sort, and two recursive functions (fib, gcd).
// gcc -O2 preserves all 16 as distinct symbols on AMD64.
func TestDetectFunctionsFromELF_StrippedC_Optimized(t *testing.T) {
	userFuncs := []string{
		"word_count", "longest_word", "vowel_count", "char_count",
		"is_printable", "checksum",
		"arr_min", "arr_max", "arr_sum", "arr_sort", "arr_find",
		"fib", "gcd",
		"report_str", "report_arr", "main",
	}

	byVA, truth, stats := measure(
		t, "gcc", "strip", []string{"-O2"},
		"testdata/stripped-app.c", userFuncs,
	)
	stats.logSummary(t)

	// report_str and report_arr are called multiple times from main
	// and must reach high confidence.
	for _, name := range []string{"report_str", "report_arr"} {
		va := truth[name]
		if c, ok := byVA[va]; !ok {
			t.Errorf("%s(0x%x): not detected", name, va)
		} else if c.Confidence != resurgo.ConfidenceHigh {
			t.Errorf("%s(0x%x): confidence=%s, want high", name, va, c.Confidence)
		}
	}

	// Full recall is required on AMD64: all 16 functions survive -O2.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 1.0x. Genuine FPs are intra-function
	// aligned addresses picked up by the boundary scanner (~0.62x baseline
	// with gcc 14.2.0).
	if stats.fpMultiplier() >= 1.0 {
		t.Errorf("false positive multiplier %.2fx >= 1.00x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_StrippedC_Optimized_ARM64 validates detection
// on a cross-compiled ARM64 optimized stripped binary and documents the
// known limitations for small leaf functions.
//
// The test cross-compiles testdata/stripped-app.c with aarch64-linux-gnu-gcc
// at -O2. On ARM64, small leaf functions (arr_min, arr_find, gcd) are packed
// at 4-byte boundaries without 16-byte alignment fill, have no call-site
// edges in the stripped binary, and are therefore undetectable by any current
// strategy. All other functions are expected at high or medium confidence.
//
// Skipped if aarch64-linux-gnu-gcc or aarch64-linux-gnu-strip are not in PATH.
func TestDetectFunctionsFromELF_StrippedC_Optimized_ARM64(t *testing.T) {
	userFuncs := []string{
		"word_count", "longest_word", "vowel_count", "char_count",
		"is_printable", "checksum",
		"arr_min", "arr_max", "arr_sum", "arr_sort", "arr_find",
		"fib", "gcd",
		"report_str", "report_arr", "main",
	}

	byVA, truth, stats := measure(
		t, "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-strip",
		[]string{"-O2"},
		"testdata/stripped-app.c", userFuncs,
	)
	stats.logSummary(t)

	// report_str and report_arr are called multiple times from main
	// and must reach high confidence on ARM64.
	for _, name := range []string{"report_str", "report_arr"} {
		va := truth[name]
		if c, ok := byVA[va]; !ok {
			t.Errorf("%s(0x%x): not detected", name, va)
		} else if c.Confidence != resurgo.ConfidenceHigh {
			t.Errorf("%s(0x%x): confidence=%s, want high", name, va, c.Confidence)
		}
	}

	// At least 13/16 functions must be found. The three known misses
	// (arr_min, arr_find, gcd) are small leaf functions with no
	// call-site edges and no 16-byte alignment gap on ARM64.
	if stats.truePositives < 13 {
		t.Errorf("true positives: %d/%d - regression? expected >= 13; missed: %v",
			stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 1.0x. Residual FPs are intra-CRT
	// jump targets (~0.44x baseline with gcc 14.2.0 aarch64-linux-gnu).
	if stats.fpMultiplier() >= 1.0 {
		t.Errorf("false positive multiplier %.2fx >= 1.00x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

