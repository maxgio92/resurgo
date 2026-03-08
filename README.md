<h1 align="center"><img src="logo.png" width="256" height="256" alt="ResurGo"></h1>

[![CI](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/maxgio92/resurgo.svg)](https://pkg.go.dev/github.com/maxgio92/resurgo)
[![GitHub Tag](https://img.shields.io/github/v/tag/maxgio92/resurgo)](https://github.com/maxgio92/resurgo/tags)

ResurGo is a Go library for static function recovery from stripped executable binaries.

## Features

- **Disassembly-based detection**: function entry recovery via three complementary signals - prologue pattern matching, call-site analysis, and alignment boundary analysis
- **DWARF CFI-based detection**: high-confidence function entries extracted from `.eh_frame` FDE records - compiler-written, survives `strip --strip-all`
- **False positive filtering**: discards intra-function jump targets and linker-generated PLT stubs from the candidate set
- **Format-agnostic core**: works on raw machine code bytes from any binary format
- **ELF convenience wrapper**: built-in support for parsing ELF executables and inferring architecture

## Supported architectures

- **x86_64** (AMD64)
- **ARM64** (AArch64)

## Detection strategies

### Disassembly-based

Resurgo disassembles the `.text` section and runs three independent signals in parallel, then merges the results:

- **Prologue matching** - recognizes architecture-specific function entry instruction sequences. See [docs/PROLOGUES.md](docs/PROLOGUES.md).
- **Call-site analysis** - extracts `CALL` and `JMP` targets; functions called or jumped to from many sites carry higher confidence. See [docs/CALLSITES.md](docs/CALLSITES.md).
- **Alignment boundary analysis** - recovers pure-leaf and never-called functions by detecting the alignment gap compilers emit between adjacent functions. See [docs/BOUNDARY.md](docs/BOUNDARY.md).

Candidates from all three signals are merged and scored. ELF-specific false-positive filters (PLT ranges, intra-function jump anchor check) are applied before the final result is returned.

### DWARF CFI-based

When the binary contains an `.eh_frame` section, resurgo parses its FDE (Frame Description Entry) records and uses their `initial_location` fields as a high-confidence function entry set. These addresses were written by the compiler - not inferred by heuristics - and are typically present in stripped ELF binaries where `.symtab` and `.debug_*` are long gone.

When `.eh_frame` is present it acts as an authoritative whitelist: disassembly candidates not covered by any FDE are dropped as noise, and FDE entries with no matching disassembly candidate are promoted directly. See [docs/CFI.md](docs/CFI.md).

## Usage

### Detect functions from a stripped ELF

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/maxgio92/resurgo"
)

func main() {
    f, err := os.Open("./myapp")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    candidates, err := resurgo.DetectFunctionsFromELF(f)
    if err != nil {
        log.Fatal(err)
    }

    for _, c := range candidates {
        fmt.Printf("0x%x: %s (confidence: %s)\n",
            c.Address, c.DetectionType, c.Confidence)
    }
}
```

#### Example output

```
0x401000: both (confidence: high)
0x401100: prologue-only (confidence: medium)
0x401200: call-target (confidence: medium)
0x401300: aligned-entry (confidence: low)
0x401400: cfi (confidence: high)
```

### Raw bytes (format-agnostic)

```go
candidates, err := resurgo.DetectFunctions(data, 0x400000, resurgo.ArchAMD64)
```

## API Reference

```go
// DetectFunctions merges prologue, call-site, and boundary signals on raw
// machine code bytes. baseAddr is the virtual address of the first byte of
// code. arch selects architecture-specific detection logic.
func DetectFunctions(code []byte, baseAddr uint64, arch Arch) ([]FunctionCandidate, error)

// DetectFunctionsFromELF parses an ELF binary, runs all detection signals,
// applies false-positive filters (PLT ranges, intra-function jump targets),
// and, when .eh_frame is present, uses CFI FDE entries as a whitelist.
// Architecture is inferred from the ELF header.
func DetectFunctionsFromELF(r io.ReaderAt) ([]FunctionCandidate, error)

// DetectPrologues scans raw machine code bytes for architecture-specific
// function prologue patterns. Works on any binary format.
func DetectPrologues(code []byte, baseAddr uint64, arch Arch) ([]Prologue, error)

// DetectProloguesFromELF parses an ELF binary and returns detected function
// prologues. Architecture is inferred from the ELF header.
func DetectProloguesFromELF(r io.ReaderAt) ([]Prologue, error)

// DetectCallSites scans raw machine code bytes for CALL and JMP instructions
// and returns their resolved target addresses. Works on any binary format.
func DetectCallSites(code []byte, baseAddr uint64, arch Arch) ([]CallSiteEdge, error)

// DetectCallSitesFromELF parses an ELF binary and returns detected call sites,
// filtered to targets within the .text section.
// Architecture is inferred from the ELF header.
func DetectCallSitesFromELF(r io.ReaderAt) ([]CallSiteEdge, error)
```

Key types:

```go
type DetectionType string

const (
    DetectionPrologueOnly DetectionType = "prologue-only"
    DetectionCallTarget   DetectionType = "call-target"
    DetectionJumpTarget   DetectionType = "jump-target"
    DetectionBoth         DetectionType = "both"
    DetectionAlignedEntry DetectionType = "aligned-entry"
    DetectionCFI          DetectionType = "cfi"
)

type FunctionCandidate struct {
    Address       uint64        `json:"address"`
    DetectionType DetectionType `json:"detection_type"`
    PrologueType  PrologueType  `json:"prologue_type,omitempty"`
    CalledFrom    []uint64      `json:"called_from,omitempty"`
    JumpedFrom    []uint64      `json:"jumped_from,omitempty"`
    Confidence    Confidence    `json:"confidence"`
}
```

## Implementation

```
+------------------+
|   ELF Binary     |
+------------------+
         |
         v
+------------------+
|   ELF Parser     |  (debug/elf)
+--------+---------+
         |
         +-------------------------------+
         |                               |
         v                               v
+------------------+           +------------------+
|  Disassembler    |           |   CFI Parser     |
|  (.text bytes)   |           |   (.eh_frame)    |
+---+---------+----+           +--------+---------+
    |         |    |                    |
    v         v    v                    v
+------+ +------+ +--------+  +------------------+
|Prolog| |Call  | |Boundary|  | FDE entry VAs    |
|ues   | |Sites | |Analysis|  | (whitelist)      |
+--+---+ +--+---+ +---+----+  +--------+---------+
   |        |         |                |
   +--------+---------+                |
            v                          |
   +------------------+                |
   | DetectFunctions  |                |
   | (merge + score)  |                |
   +--------+---------+                |
            |                          |
            v                          |
   +------------------+                |
   |   FP Filters     | <--------------+
   |  PLT, anchor,    |
   |  CFI whitelist   |
   +--------+---------+
            |
            v
   +------------------+
   |[]FunctionCandidate|
   +------------------+
```

## Limitations

- Reports addresses only - no symbol names on stripped binaries
- Disassembly signals are heuristic; CRT scaffolding on aligned addresses can still produce false positives when `.eh_frame` is absent
- Linear disassembly - indirect jumps and computed addresses are not resolved

## Dependencies

- **Go 1.25.7+**
- [`golang.org/x/arch`](https://pkg.go.dev/golang.org/x/arch) - x86 and ARM64 disassembler
- `debug/elf` (standard library) - ELF parser

## References

- [System V AMD64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [DWARF 5 Standard](https://dwarfstd.org/dwarf5std.html)
- [Linux Standard Base - Exception Frames](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
