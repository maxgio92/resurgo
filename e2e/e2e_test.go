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

// statsRow is a labeled detectionStats entry for logStatsTable.
type statsRow struct {
	label string
	stats detectionStats
}

// logStatsTable prints a summary table with one row per entry in rows.
func logStatsTable(t *testing.T, rows ...statsRow) {
	t.Helper()
	t.Logf("%-22s  %6s  %5s  %7s  %7s  %4s  %8s",
		"", "total", "tp", "recall", "missed", "fp", "fp_mult")
	for _, r := range rows {
		t.Logf("%-22s  %6d  %5d  %6.0f%%  %7d  %4d  %7.2fx",
			r.label,
			r.stats.total, r.stats.truePositives, r.stats.tpRate(),
			r.stats.total-r.stats.truePositives,
			r.stats.falsePositives, r.stats.fpMultiplier())
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

// withoutCRT returns a symbol filter that excludes zero-size STT_FUNC symbols
// from the ground-truth set. CRT stubs (deregister_tm_clones, frame_dummy,
// call_weak_fn, _init, _fini, etc.) are all zero-size in the debug file:
// they have no real body and no .eh_frame FDE entries, so they cannot be
// recovered by CFI-based detection on stripped binaries. Detecting them by
// name would require maintaining a fragile allowlist; size == 0 is a
// structural property detectable directly from the ELF.
func withoutCRT() func(elf.Symbol) bool {
	return func(s elf.Symbol) bool {
		return s.Size > 0
	}
}

// allFunctionVAs returns the set of STT_FUNC virtual addresses in binPath,
// keyed by VA and valued by the full elf.Symbol. Symbols with VA=0 (undefined
// imports) are excluded. Optional filters further narrow the set: a symbol is
// included only when all filters return true.
func allFunctionVAs(t *testing.T, binPath string, filters ...func(elf.Symbol) bool) map[uint64]elf.Symbol {
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

	result := make(map[uint64]elf.Symbol)
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Value == 0 {
			continue
		}
		include := true
		for _, filter := range filters {
			if !filter(sym) {
				include = false
				break
			}
		}
		if include {
			result[sym.Value] = sym
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

	logStatsTable(t, statsRow{"result", stats})
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

	logStatsTable(t, statsRow{"result", stats})
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

	logStatsTable(t, statsRow{"result", stats})
}

// TestDetectFunctionsFromELF_RealWorld_Grep_AMD64 validates detection on a
// real-world AMD64 stripped binary: Debian grep 3.11-4 compiled with full
// gcc hardening.
//
// The test runs four filter pipeline configurations in order to verify each
// filter's contribution to FP reduction:
//
//	none -> plt -> plt+cet -> plt+cet+cfi (default)
//
// Baseline numbers (trixie, gcc 14.2.0, 326 user functions):
//
//	none:    247 TP, 1073 FP (3.29x)
//	plt:     247 TP,  942 FP (2.89x)
//	plt+cet: 246 TP,  536 FP (1.64x)
//	plt+cet+cfi (default): 326 TP, 2 FP (0.01x)
//
// Assertions:
//   - FP decreases at each pipeline step
//   - Full pipeline recall >= PLT-only recall (FDE recovers what CET dropped)
//   - Default pipeline recall >= 98%, FP multiplier < 0.01x

//
// Skipped if /usr/bin/grep is not stripped or grep-dbgsym is not installed.
func TestDetectFunctionsFromELF_RealWorld_Grep_AMD64(t *testing.T) {
	const binPath = "/usr/bin/grep"

	if !isStripped(t, binPath) {
		t.Skip("grep binary is not stripped; test requires stripped system binary")
	}

	dbgPath, err := findDebugFile(t, binPath)
	if err != nil {
		t.Skipf("grep-dbgsym not available: %v", err)
	}

	allFuncs := allFunctionVAs(t, dbgPath)
	allFuncsNoCRT := allFunctionVAs(t, dbgPath, withoutCRT())
	if len(allFuncs) == 0 {
		t.Fatal("no STT_FUNC symbols in debug file; ground truth is empty")
	}

	// crtVAs is the set of VAs excluded from the no_crt ground truth.
	// Candidates at these addresses are ignored when scoring against
	// allFuncsNoCRT: they are real functions, just out of scope.
	crtVAs := make(map[uint64]struct{}, len(allFuncs)-len(allFuncsNoCRT))
	for va := range allFuncs {
		if _, ok := allFuncsNoCRT[va]; !ok {
			crtVAs[va] = struct{}{}
		}
	}

	f, err := os.Open(binPath)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", binPath, err)
	}
	defer f.Close()

	// run scores detection results against gt. opts == nil uses the default
	// pipeline. Candidates in crtVAs are skipped (neither TP nor FP).
	run := func(gt map[uint64]elf.Symbol, opts []resurgo.Option) (detectionStats, []resurgo.FunctionCandidate) {
		candidates, runErr := resurgo.DetectFunctionsFromELF(f, opts...)
		if runErr != nil {
			t.Fatalf("DetectFunctionsFromELF: %v", runErr)
		}
		var s detectionStats
		s.total = len(gt)
		for _, c := range candidates {
			if _, ok := gt[c.Address]; ok {
				s.truePositives++
			} else if _, isCRT := crtVAs[c.Address]; !isCRT {
				s.falsePositives++
			}
		}
		return s, candidates
	}

	type pipelineCase struct {
		label string
		opts  []resurgo.Option // nil = default pipeline
	}
	pipeline := []pipelineCase{
		{"none", []resurgo.Option{resurgo.WithFilters()}},
		{"plt", []resurgo.Option{resurgo.WithFilters(resurgo.PLTFilter)}},
		{"plt+cet", []resurgo.Option{resurgo.WithFilters(resurgo.PLTFilter, resurgo.CETFilter)}},
		{"plt+cet+cfi (default)", nil},
	}

	results := make([]detectionStats, len(pipeline))
	rows := make([]statsRow, len(pipeline))
	var fullCandidates []resurgo.FunctionCandidate
	for i, c := range pipeline {
		var cands []resurgo.FunctionCandidate
		results[i], cands = run(allFuncsNoCRT, c.opts)
		rows[i] = statsRow{c.label, results[i]}
		if i == len(pipeline)-1 {
			fullCandidates = cands
		}
	}

	// Compute CRT-inclusive stats for the full pipeline run. Insert before
	// the plt+cet+cfi (default) row so the default pipeline result is the last line.
	var fullAll detectionStats
	fullAll.total = len(allFuncs)
	for _, c := range fullCandidates {
		if _, ok := allFuncs[c.Address]; ok {
			fullAll.truePositives++
		} else {
			fullAll.falsePositives++
		}
	}
	last := rows[len(rows)-1]
	rows[len(rows)-1] = statsRow{"plt+cet+cfi (with crt)", fullAll}
	rows = append(rows, last)
	logStatsTable(t, rows...)

	// Each filter stage must reduce FP.
	for i := 1; i < len(pipeline); i++ {
		if results[i].falsePositives >= results[i-1].falsePositives {
			t.Errorf("%s did not reduce FP vs %s: %d -> %d",
				pipeline[i].label, pipeline[i-1].label,
				results[i-1].falsePositives, results[i].falsePositives)
		}
	}

	// Each pipeline step must reach at least 70% recall. Guards against
	// disassembly regressions that FDE recovery would otherwise mask.
	for i, r := range results {
		if r.tpRate() < 70.0 {
			t.Errorf("%s: recall %.1f%% < 70.0%%: regression?",
				pipeline[i].label, r.tpRate())
		}
	}

	// plt+cet+cfi (default) recall must be >= PLT-only (FDE recovers what CET dropped).
	pltIdx, fullIdx := 1, len(pipeline)-1
	if results[fullIdx].truePositives < results[pltIdx].truePositives {
		t.Errorf("plt+cet+cfi (default) regressed recall vs plt: tp %d -> %d",
			results[pltIdx].truePositives, results[fullIdx].truePositives)
	}

	// Log FP and missed details for the full pipeline run.
	detectedVAs := make(map[uint64]struct{}, len(fullCandidates))
	for _, c := range fullCandidates {
		detectedVAs[c.Address] = struct{}{}
	}
	for _, c := range fullCandidates {
		if _, ok := allFuncs[c.Address]; !ok {
			t.Logf("false_positive: 0x%x  %s  %s",
				c.Address, c.DetectionType, c.Confidence)
		}
	}
	for va, sym := range allFuncs {
		if _, found := detectedVAs[va]; found {
			continue
		}
		if sym.Size == 0 {
			t.Logf("missed (crt):  0x%x  %s", va, sym.Name)
		} else {
			t.Logf("missed:        0x%x  %s", va, sym.Name)
		}
	}

	// At least 98% recall. Baseline (grep 3.11-4, gcc 14.2.0): 98.2%.
	if fullAll.tpRate() < 98.0 {
		t.Errorf("true positive rate %.1f%% < 98.0%%: regression?", fullAll.tpRate())
	}
	// FP multiplier must stay below 0.01x. Baseline: 0.006x.
	if fullAll.fpMultiplier() >= 0.01 {
		t.Errorf("false positive multiplier %.3fx >= 0.010x: too noisy",
			fullAll.fpMultiplier())
	}
}

// TestDetectFunctionsFromELF_RealWorld_Grep_ARM64 validates detection on a
// real-world ARM64 stripped binary: the same Debian grep package built for
// arm64.
//
// The binary is extracted from grep:arm64 to /opt/grep-arm64/usr/bin/grep to
// avoid conflicting with grep:amd64 on /usr/bin/grep. Debug symbols are
// resolved via the standard .build-id path after extracting grep-dbgsym:arm64
// to /.
//
// Three filter pipeline configurations are tested. CET is not included as a
// separate step because it is a no-op on ARM64.
//
//	none -> plt -> plt+cet+cfi (default)
//
// Skipped if the binary or its debug file is not present (e.g. outside the
// e2e Docker image or CI container).
func TestDetectFunctionsFromELF_RealWorld_Grep_ARM64(t *testing.T) {
	const binPath = "/opt/grep-arm64/usr/bin/grep"

	if _, err := os.Stat(binPath); err != nil {
		t.Skipf("ARM64 grep binary not installed at %s: %v", binPath, err)
	}

	if !isStripped(t, binPath) {
		t.Skip("ARM64 grep binary is not stripped; test requires a stripped binary")
	}

	dbgPath, err := findDebugFile(t, binPath)
	if err != nil {
		t.Skipf("grep-dbgsym:arm64 not available: %v", err)
	}

	allFuncs := allFunctionVAs(t, dbgPath)
	allFuncsNoCRT := allFunctionVAs(t, dbgPath, withoutCRT())
	if len(allFuncs) == 0 {
		t.Fatal("no STT_FUNC symbols in debug file; ground truth is empty")
	}

	// crtVAs is the set of VAs excluded from the no_crt ground truth.
	// Candidates at these addresses are ignored when scoring against
	// allFuncsNoCRT: they are real functions, just out of scope.
	crtVAs := make(map[uint64]struct{}, len(allFuncs)-len(allFuncsNoCRT))
	for va := range allFuncs {
		if _, ok := allFuncsNoCRT[va]; !ok {
			crtVAs[va] = struct{}{}
		}
	}

	f, err := os.Open(binPath)
	if err != nil {
		t.Fatalf("os.Open(%s): %v", binPath, err)
	}
	defer f.Close()

	// run scores detection results against gt. opts == nil uses the default
	// pipeline. Candidates in crtVAs are skipped (neither TP nor FP).
	run := func(gt map[uint64]elf.Symbol, opts []resurgo.Option) (detectionStats, []resurgo.FunctionCandidate) {
		candidates, runErr := resurgo.DetectFunctionsFromELF(f, opts...)
		if runErr != nil {
			t.Fatalf("DetectFunctionsFromELF: %v", runErr)
		}
		var s detectionStats
		s.total = len(gt)
		for _, c := range candidates {
			if _, ok := gt[c.Address]; ok {
				s.truePositives++
			} else if _, isCRT := crtVAs[c.Address]; !isCRT {
				s.falsePositives++
			}
		}
		return s, candidates
	}

	type pipelineCase struct {
		label string
		opts  []resurgo.Option // nil = default pipeline
	}
	pipeline := []pipelineCase{
		{"none", []resurgo.Option{resurgo.WithFilters()}},
		{"plt", []resurgo.Option{resurgo.WithFilters(resurgo.PLTFilter)}},
		{"plt+cet+cfi (default)", nil},
	}

	results := make([]detectionStats, len(pipeline))
	rows := make([]statsRow, len(pipeline))
	var fullCandidates []resurgo.FunctionCandidate
	for i, c := range pipeline {
		var cands []resurgo.FunctionCandidate
		results[i], cands = run(allFuncsNoCRT, c.opts)
		rows[i] = statsRow{c.label, results[i]}
		if i == len(pipeline)-1 {
			fullCandidates = cands
		}
	}

	// Compute CRT-inclusive stats for the full pipeline run. Insert before
	// the plt+cet+cfi (default) row so the default pipeline result is the last line.
	var fullAll detectionStats
	fullAll.total = len(allFuncs)
	for _, c := range fullCandidates {
		if _, ok := allFuncs[c.Address]; ok {
			fullAll.truePositives++
		} else {
			fullAll.falsePositives++
		}
	}
	last := rows[len(rows)-1]
	rows[len(rows)-1] = statsRow{"plt+cet+cfi (with crt)", fullAll}
	rows = append(rows, last)
	logStatsTable(t, rows...)

	// Each filter stage must reduce FP.
	for i := 1; i < len(pipeline); i++ {
		if results[i].falsePositives >= results[i-1].falsePositives {
			t.Errorf("%s did not reduce FP vs %s: %d -> %d",
				pipeline[i].label, pipeline[i-1].label,
				results[i-1].falsePositives, results[i].falsePositives)
		}
	}

	// Each pipeline step must reach at least 70% recall. Guards against
	// disassembly regressions that FDE recovery would otherwise mask.
	for i, r := range results {
		if r.tpRate() < 70.0 {
			t.Errorf("%s: recall %.1f%% < 70.0%%: regression?",
				pipeline[i].label, r.tpRate())
		}
	}

	// plt+cet+cfi (default) recall must be >= PLT-only (FDE recovers missed functions).
	pltIdx, fullIdx := 1, len(pipeline)-1
	if results[fullIdx].truePositives < results[pltIdx].truePositives {
		t.Errorf("plt+cet+cfi (default) regressed recall vs plt: tp %d -> %d",
			results[pltIdx].truePositives, results[fullIdx].truePositives)
	}

	// Log FP and missed details for the full pipeline run.
	detectedVAs := make(map[uint64]struct{}, len(fullCandidates))
	for _, c := range fullCandidates {
		detectedVAs[c.Address] = struct{}{}
	}
	for _, c := range fullCandidates {
		if _, ok := allFuncs[c.Address]; !ok {
			t.Logf("false_positive: 0x%x  %s  %s",
				c.Address, c.DetectionType, c.Confidence)
		}
	}
	for va, sym := range allFuncs {
		if _, found := detectedVAs[va]; found {
			continue
		}
		if sym.Size == 0 {
			t.Logf("missed (crt):  0x%x  %s", va, sym.Name)
		} else {
			t.Logf("missed:        0x%x  %s", va, sym.Name)
		}
	}

	// At least 98% recall. Baseline (grep 3.11-4, arm64): 98.97%.
	if fullAll.tpRate() < 98.0 {
		t.Errorf("true positive rate %.1f%% < 98.0%%: regression?", fullAll.tpRate())
	}
	// FP multiplier must stay below 0.01x. Baseline: 0.000x.
	if fullAll.fpMultiplier() >= 0.01 {
		t.Errorf("false positive multiplier %.3fx >= 0.010x: too noisy",
			fullAll.fpMultiplier())
	}
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

	logStatsTable(t, statsRow{"result", stats})
}
