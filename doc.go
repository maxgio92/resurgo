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
//     making CFI the highest-confidence source available on stripped binaries.
//
// The primary entry point for most callers is [DetectFunctionsFromELF], which
// accepts an [io.ReaderAt] (e.g. *os.File), infers the target architecture from
// the ELF header, and returns a deduplicated, filtered slice of
// [FunctionCandidate] values. Each candidate carries its virtual address,
// detection type, and a confidence rating.
//
// For format-agnostic use (non-ELF binaries, raw memory dumps) use
// [DetectFunctions], which accepts raw machine code bytes and a base address.
//
// Lower-level APIs ([DetectPrologues], [DetectCallSites] and their FromELF
// variants) are available when only a single signal is needed.
//
// Supported architectures: x86_64 (AMD64) and ARM64 (AArch64).
package resurgo
