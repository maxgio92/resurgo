//go:build e2e

package e2e_test

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
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

// findDebugFile locates the external debug file for binPath using the
// GNU build-id convention: /usr/lib/debug/.build-id/XX/XXX...XX.debug.
// Returns an error if .note.gnu.build-id is absent or the debug file is not
// installed (e.g. the matching -dbgsym package is not present).
func findDebugFile(t *testing.T, binPath string) (string, error) {
	t.Helper()
	f, err := elf.Open(binPath)
	if err != nil {
		return "", fmt.Errorf("elf.Open: %w", err)
	}
	defer f.Close()

	sect := f.Section(".note.gnu.build-id")
	if sect == nil {
		return "", fmt.Errorf(".note.gnu.build-id not found in %s", binPath)
	}
	data, err := sect.Data()
	if err != nil {
		return "", fmt.Errorf("read .note.gnu.build-id: %w", err)
	}

	// ELF note layout (LE): namesz uint32, descsz uint32, ntype uint32,
	// name[namesz] padded to 4 bytes, desc[descsz] = build ID bytes.
	if len(data) < 12 {
		return "", fmt.Errorf("build-id note too short (%d bytes)", len(data))
	}
	namesz := int(binary.LittleEndian.Uint32(data[0:4]))
	descsz := int(binary.LittleEndian.Uint32(data[4:8]))
	offset := 12 + (namesz+3)&^3 // skip name, padded to 4-byte boundary
	if offset+descsz > len(data) {
		return "", fmt.Errorf("build-id note malformed: offset=%d descsz=%d len=%d",
			offset, descsz, len(data))
	}
	buildID := data[offset : offset+descsz]
	hex := fmt.Sprintf("%x", buildID)
	dbgPath := fmt.Sprintf("/usr/lib/debug/.build-id/%s/%s.debug", hex[:2], hex[2:])
	if _, err := os.Stat(dbgPath); err != nil {
		return "", fmt.Errorf("debug file not installed: %s", dbgPath)
	}
	return dbgPath, nil
}

// isStripped returns true when binPath has no symbol table (.symtab).
func isStripped(t *testing.T, binPath string) bool {
	t.Helper()
	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatalf("elf.Open(%s): %v", binPath, err)
	}
	defer f.Close()
	_, err = f.Symbols()
	return err != nil
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
// Source: testdata/stripped-app.c - the same 16-function realistic fixture
// used by the optimized tests. At -O0 -fno-inline all 16 functions survive
// as distinct symbols; 100% recall is required.
func TestDetectFunctionsFromELF_StrippedC_Unoptimized(t *testing.T) {
	userFuncs := []string{
		"word_count", "longest_word", "vowel_count", "char_count",
		"is_printable", "checksum",
		"arr_min", "arr_max", "arr_sum", "arr_sort", "arr_find",
		"fib", "gcd",
		"report_str", "report_arr", "main",
	}

	byVA, truth, stats := measure(
		t, "gcc", "strip", []string{"-O0", "-fno-inline"},
		"testdata/stripped-app.c", userFuncs,
	)
	stats.logSummary(t)

	// Full recall is required: -O0 preserves all 16 functions.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 0.5x. PLT stubs are filtered and
	// CRT functions are excluded from the FP count.
	if stats.fpMultiplier() >= 0.5 {
		t.Errorf("false positive multiplier %.2fx >= 0.50x: detector is too noisy",
			stats.fpMultiplier())
	}

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

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_StrippedC_Unoptimized_ARM64 verifies that
// DetectFunctionsFromELF finds all user-defined functions in a
// cross-compiled ARM64 stripped binary compiled without optimisation.
//
// At -O0 -fno-inline all 16 functions survive as distinct symbols.
// Unlike the -O2 case, small leaf functions are not packed at 4-byte
// boundaries without prologues, so 100% recall is expected.
//
// Skipped if aarch64-linux-gnu-gcc or aarch64-linux-gnu-strip are not in PATH.
func TestDetectFunctionsFromELF_StrippedC_Unoptimized_ARM64(t *testing.T) {
	userFuncs := []string{
		"word_count", "longest_word", "vowel_count", "char_count",
		"is_printable", "checksum",
		"arr_min", "arr_max", "arr_sum", "arr_sort", "arr_find",
		"fib", "gcd",
		"report_str", "report_arr", "main",
	}

	byVA, truth, stats := measure(
		t, "aarch64-linux-gnu-gcc", "aarch64-linux-gnu-strip",
		[]string{"-O0", "-fno-inline"},
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

	// Full recall is required: -O0 preserves all 16 functions on ARM64.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 0.5x.
	if stats.fpMultiplier() >= 0.5 {
		t.Errorf("false positive multiplier %.2fx >= 0.50x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_StrippedC_Optimized validates that
// DetectFunctionsFromELF correctly identifies all user functions in a
// stripped C binary compiled at -O2.
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

	// Full recall is required: all 16 functions survive -O2 on AMD64.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 0.5x (~0.12x baseline with gcc 14.2.0).
	if stats.fpMultiplier() >= 0.5 {
		t.Errorf("false positive multiplier %.2fx >= 0.50x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_RealWorld_Grep validates detection on a real-world
// AMD64 stripped binary: Debian grep 3.11-4 compiled with full gcc hardening.
//
// Ground truth: all 333 STT_FUNC symbols from the matching grep-dbgsym debug
// file (198 global + 134 local static functions, plus 1 GLIBC import).
// The binary at /usr/bin/grep is already stripped.
//
// Baseline numbers (trixie, gcc 14.2.0, with .eh_frame detection):
//   - true positives:  326/333 (98%)
//   - false positives: 2 (0.01x)
//
// The 7 missed functions are not covered by .eh_frame FDE entries (likely
// hand-written assembly or linker-synthesised stubs without .cfi_* directives).
// The 2 false positives are addresses in .text that are not STT_FUNC symbols
// in the debug file but are targeted by FDE entries (possibly inlined or
// renamed across versions).
//
// Skipped if /usr/bin/grep is not stripped or grep-dbgsym is not installed.
func TestDetectFunctionsFromELF_RealWorld_Grep(t *testing.T) {
	const binPath = "/usr/bin/grep"

	if !isStripped(t, binPath) {
		t.Skip("grep binary is not stripped; test requires stripped system binary")
	}

	dbgPath, err := findDebugFile(t, binPath)
	if err != nil {
		t.Skipf("grep-dbgsym not available: %v", err)
	}

	// Ground truth: every STT_FUNC symbol in the debug file.
	allFuncs := allFunctionVAs(t, dbgPath)
	total := len(allFuncs)
	if total == 0 {
		t.Fatal("no STT_FUNC symbols in debug file; ground truth is empty")
	}

	f, err := os.Open(binPath)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", binPath, err)
	}
	defer f.Close()

	candidates, err := resurgo.DetectFunctionsFromELF(f)
	if err != nil {
		t.Fatalf("DetectFunctionsFromELF: %v", err)
	}

	var stats detectionStats
	stats.total = total
	for _, c := range candidates {
		if _, ok := allFuncs[c.Address]; ok {
			stats.truePositives++
		} else {
			stats.falsePositives++
		}
	}
	// Function names are not available from a stripped binary; log in the
	// same format as logSummary but without the name list.
	missed := stats.total - stats.truePositives
	t.Logf("true_positives:   %d/%d (%.0f%%)", stats.truePositives, stats.total, stats.tpRate())
	t.Logf("missed:           %d/%d (%.0f%%)", missed, stats.total, stats.missedRate())
	t.Logf("false_positives:  %d (%.2fx per real function)", stats.falsePositives, stats.fpMultiplier())

	// At least 95% recall. Baseline (grep 3.11-4, gcc 14.2.0): 98%.
	if stats.tpRate() < 95.0 {
		t.Errorf("true positive rate %.1f%% < 95.0%%: regression?", stats.tpRate())
	}

	// FP multiplier must stay below 0.1x. Baseline: 0.01x.
	if stats.fpMultiplier() >= 0.1 {
		t.Errorf("false positive multiplier %.2fx >= 0.10x: too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.fpMultiplier())
}

// TestDetectFunctionsFromELF_StrippedC_Optimized_ARM64 validates detection
// on a cross-compiled ARM64 optimized stripped binary.
//
// The test cross-compiles testdata/stripped-app.c with aarch64-linux-gnu-gcc
// at -O2. Small leaf functions (arr_min, arr_find, gcd) are packed at 4-byte
// boundaries without 16-byte alignment fill and have no call-site edges in the
// stripped binary, but are recovered via .eh_frame FDE entries. Full recall
// is now expected.
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

	// Full recall is required: .eh_frame recovers all 16 functions on ARM64,
	// including small leaf functions invisible to disassembly heuristics.
	if stats.truePositives < stats.total {
		t.Errorf("true positive rate %.0f%% (%d/%d): expected 100%%; missed: %v",
			stats.tpRate(), stats.truePositives, stats.total, stats.missed)
	}

	// FP multiplier must stay below 0.1x. Baseline: 0.00x.
	if stats.fpMultiplier() >= 0.1 {
		t.Errorf("false positive multiplier %.2fx >= 0.10x: detector is too noisy",
			stats.fpMultiplier())
	}

	t.Logf("snapshot: tp_rate=%.0f%% missed=%.0f%% fp_multiplier=%.2fx",
		stats.tpRate(), stats.missedRate(), stats.fpMultiplier())
}

