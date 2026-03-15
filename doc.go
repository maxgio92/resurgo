// Package resurgo provides static function recovery from stripped ELF binaries.
//
// It combines two complementary detection strategies:
//
//   - Disassembly-based: three parallel signals (prologue pattern matching,
//     call-site analysis, and alignment boundary analysis) are merged and scored
//     to produce a ranked set of function candidates.
//
//   - DWARF CFI-based: when the binary contains an .eh_frame section, the
//     initial_location fields from its FDE records are used as an authoritative
//     whitelist. These addresses were written by the compiler and survive
//     stripping, making CFI the highest-confidence source available.
//
// The primary entry point is [DetectFunctionsFromELF], which accepts a parsed
// [*elf.File], runs all detectors and filters, and returns a deduplicated,
// filtered slice of [FunctionCandidate] values.
//
// For format-agnostic use (non-ELF binaries, raw memory dumps) the lower-level
// [DetectPrologues] and [DetectCallSites] APIs accept raw machine code bytes.
//
// Supported architectures: x86_64 (AMD64) and ARM64 (AArch64).
package resurgo
