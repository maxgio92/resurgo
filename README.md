<h1 align="center"><img src="logo.png" width="256" height="256" alt="ResurGo"></h1>

[![CI](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/maxgio92/resurgo.svg)](https://pkg.go.dev/github.com/maxgio92/resurgo)
[![GitHub Tag](https://img.shields.io/github/v/tag/maxgio92/resurgo)](https://github.com/maxgio92/resurgo/tags)

ResurGo is a Go library for static function recovery from executable binaries.

It works with raw bytes from any binary format as well as parsing ELF files.

## Features

- **Prologue-Based Detection**: Recognizes common function entry patterns by instruction analysis
- **Call-Site Analysis**: Identifies functions through CALL and JMP target extraction
- **Boundary Analysis**: Recovers leaf and never-called functions via compiler alignment gaps
- **False Positive Filtering**: Discards intra-function jump targets (anchor-range filter) and linker-generated PLT stubs (section-range filter) from the candidate list
- **Format-Agnostic Core**: Works on raw machine code bytes from any binary format
- **ELF Convenience Wrapper**: Built-in support for parsing ELF executables
- **Pattern Classification**: Labels detected functions by detection type and confidence

## Supported architectures

- **x86_64** (AMD64)
- **ARM64** (AArch64)

## Supported function metadata

### Function prologues

resurgo detects the following function prologue patterns:

**x86_64:**
- `classic`  - push rbp; mov rbp, rsp
- `no-frame-pointer`  - sub rsp, imm
- `push-only`  - push <callee-saved-reg>
- `lea-based`  - lea rsp, [rsp-imm]

**ARM64:**
- `stp-frame-pair`  - stp x29, x30, [sp, #-N]!; mov x29, sp
- `str-lr-preindex`  - str x30, [sp, #-N]!
- `sub-sp`  - sub sp, sp, #N
- `stp-only`  - stp x29, x30, [sp, #-N]!

For detailed explanations of each pattern, see [docs/PROLOGUES.md](docs/PROLOGUES.md).

### Call sites

resurgo also identifies functions through call site analysis by detecting `CALL` and `JMP` instructions and extracting their target addresses. This approach:

- **Works on optimized code** where prologues may be omitted
- **Is compiler-agnostic** (all compilers generate call instructions)
- **Provides confidence scoring** based on instruction type and addressing mode
- **Can be combined with prologue detection** for higher-confidence function identification

**Supported call site types:**
- `call`  - Function calls (high confidence for direct calls)
- `jump`  - Jumps (medium confidence for unconditional, low for conditional)

**Addressing modes:**
- `pc-relative`  - PC-relative addressing (can be resolved statically)
- `absolute`  - Absolute addressing (can be resolved statically)
- `register-indirect`  - Register-based addressing (cannot be resolved statically)

**Confidence levels:**
- `high`  - Direct CALL instructions (almost always function calls)
- `medium`  - Unconditional JMP (could be tail calls or internal jumps)
- `low`  - Conditional jumps (usually intra-function branches)
- `none`  - Register-indirect (cannot be statically resolved)

For detailed explanations, see [docs/CALLSITES.md](docs/CALLSITES.md).

### Boundary analysis

resurgo also recovers function entries through boundary analysis by reading the alignment gap compilers emit between adjacent functions. When a function ends before the next 16-byte boundary, the compiler fills the dead space with NOP bytes to align the next function entry. This gap is the signal.

This strategy targets functions invisible to the other two:

- **Pure-leaf functions** with no frame setup and no callers (inlined or compile-time evaluated)

**Pattern:**
```
<previous function>
    ret                ← function terminator
    nop nop ...        ← compiler alignment fill
<16-byte aligned addr> ← new function entry detected here
```

**Terminators recognised:**
- `ret` / `lret` — the primary signal; nothing falls through after a return
- Backward unconditional `jmp` — inter-function tail calls; forward `jmp`s are excluded as they indicate intra-function branches

**Confidence:** `low` — the pattern reliably identifies that *something* starts at the aligned address but cannot distinguish user functions from compiler-injected runtime scaffolding.

For detailed explanations, see [docs/BOUNDARY.md](docs/BOUNDARY.md).

## Usage

### Detect function prologues

Import resurgo in your Go project:

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

    prologues, err := resurgo.DetectProloguesFromELF(f)
    if err != nil {
        log.Fatal(err)
    }

    for _, p := range prologues {
        fmt.Printf("[%s] 0x%x: %s\n", p.Type, p.Address, p.Instructions)
    }
}
```

#### Example output

```
[classic] 0x401000: push rbp; mov rbp, rsp
[classic] 0x401020: push rbp; mov rbp, rsp
[no-frame-pointer] 0x401040: sub rsp, 0x20
[push-only] 0x401060: push rbx
```

### Detect call sites

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

    edges, err := resurgo.DetectCallSitesFromELF(f)
    if err != nil {
        log.Fatal(err)
    }

    for _, e := range edges {
        fmt.Printf("[%s] 0x%x -> 0x%x (%s, %s)\n",
            e.Type, e.SourceAddr, e.TargetAddr, e.AddressMode, e.Confidence)
    }
}
```

#### Example output

```
[call] 0x401005 -> 0x401100 (pc-relative, high)
[call] 0x40102a -> 0x401200 (pc-relative, high)
[jump] 0x401050 -> 0x401080 (pc-relative, medium)
```

### Combined analysis

Combine prologue and call site detection for higher-confidence function identification:

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/maxgio92/resurgo"
)

func main() {
    // Read binary
    data, err := os.ReadFile("./myapp.bin")
    if err != nil {
        log.Fatal(err)
    }

    // Detect functions using both signals
    candidates, err := resurgo.DetectFunctions(data, 0x400000, resurgo.ArchAMD64)
    if err != nil {
        log.Fatal(err)
    }

    for _, c := range candidates {
        fmt.Printf("0x%x: %s (confidence: %s)\n",
            c.Address, c.DetectionType, c.Confidence)
        if len(c.CalledFrom) > 0 {
            fmt.Printf("  Called from: %d locations\n", len(c.CalledFrom))
        }
    }
}
```

#### Example output

```
0x401000: both (confidence: high)
  Called from: 3 locations
0x401100: prologue-only (confidence: medium)
0x401200: call-target (confidence: medium)
  Called from: 1 locations
```

## API Reference

**Functions:**

```go
// Prologue detection  - works on raw machine code bytes, no I/O.
// arch selects architecture-specific detection logic.
func DetectPrologues(code []byte, baseAddr uint64, arch Arch) ([]Prologue, error)

// Convenience wrapper  - parses ELF from the reader, extracts .text, calls DetectPrologues.
// Architecture is inferred from the ELF header.
func DetectProloguesFromELF(r io.ReaderAt) ([]Prologue, error)

// Call site analysis  - detects CALL and JMP instructions and extracts target addresses.
func DetectCallSites(code []byte, baseAddr uint64, arch Arch) ([]CallSiteEdge, error)

// Convenience wrapper  - parses ELF from the reader, extracts .text, calls DetectCallSites.
// Filters results to only include targets within the .text section.
func DetectCallSitesFromELF(r io.ReaderAt) ([]CallSiteEdge, error)

// Combined analysis  - merges prologue and call site detection for higher confidence.
// Functions detected by both methods receive the highest confidence rating.
func DetectFunctions(code []byte, baseAddr uint64, arch Arch) ([]FunctionCandidate, error)

// Convenience wrapper  - parses ELF from the reader, extracts .text, calls DetectFunctions,
// then applies FP filters (PLT section ranges, intra-function jump targets).
func DetectFunctionsFromELF(r io.ReaderAt) ([]FunctionCandidate, error)
```

**Types:**

```go
type Arch string

const (
    ArchAMD64 Arch = "amd64"
    ArchARM64 Arch = "arm64"
)

type PrologueType string

// x86_64 prologue types
const (
    PrologueClassic        PrologueType = "classic"
    PrologueNoFramePointer PrologueType = "no-frame-pointer"
    ProloguePushOnly       PrologueType = "push-only"
    PrologueLEABased       PrologueType = "lea-based"
)

// ARM64 prologue types
const (
    PrologueSTPFramePair  PrologueType = "stp-frame-pair"
    PrologueSTRLRPreIndex PrologueType = "str-lr-preindex"
    PrologueSubSP         PrologueType = "sub-sp"
    PrologueSTPOnly       PrologueType = "stp-only"
)

type Prologue struct {
    Address      uint64       `json:"address"`
    Type         PrologueType `json:"type"`
    Instructions string       `json:"instructions"`
}

// Call site types
type CallSiteType string

const (
    CallSiteCall CallSiteType = "call"
    CallSiteJump CallSiteType = "jump"
)

type AddressingMode string

const (
    AddressingModePCRelative      AddressingMode = "pc-relative"
    AddressingModeAbsolute        AddressingMode = "absolute"
    AddressingModeRegisterIndirect AddressingMode = "register-indirect"
)

type Confidence string

const (
    ConfidenceHigh   Confidence = "high"
    ConfidenceMedium Confidence = "medium"
    ConfidenceLow    Confidence = "low"
    ConfidenceNone   Confidence = "none"
)

type CallSiteEdge struct {
    SourceAddr  uint64         `json:"source_addr"`
    TargetAddr  uint64         `json:"target_addr"`
    Type        CallSiteType   `json:"type"`
    AddressMode AddressingMode `json:"address_mode"`
    Confidence  Confidence     `json:"confidence"`
}

// Combined analysis types
type DetectionType string

const (
    DetectionPrologueOnly DetectionType = "prologue-only"
    DetectionCallTarget   DetectionType = "call-target"
    DetectionJumpTarget   DetectionType = "jump-target"
    DetectionBoth         DetectionType = "both"          // Prologue + called/jumped to
    DetectionAlignedEntry DetectionType = "aligned-entry" // Boundary analysis (ret+nop+aligned)
)

type FunctionCandidate struct {
    Address       uint64          `json:"address"`
    DetectionType DetectionType   `json:"detection_type"`
    PrologueType  PrologueType    `json:"prologue_type,omitempty"`
    CalledFrom    []uint64        `json:"called_from,omitempty"`
    JumpedFrom    []uint64        `json:"jumped_from,omitempty"`
    Confidence    Confidence      `json:"confidence"`
}
```

`DetectPrologues` accepts raw bytes, a base virtual address, and a target architecture, making it format-agnostic (works with ELF, PE, Mach-O, raw dumps).

`DetectProloguesFromELF` accepts an `io.ReaderAt` (e.g. `*os.File`), infers the architecture from the ELF header, and handles parsing internally.

## Implementation

### Architecture

```
┌─────────────────┐
│   ELF Binary    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ELF Parser     │ ← debug/elf package
│  (.text section)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Disassembler   │ ← golang.org/x/arch (x86asm / arm64asm)
│   (ASM decode)  │
└────────┬────────┘
         │
    ┌────┼────────────┐
    ▼    ▼            ▼
┌───────┐ ┌─────────┐ ┌──────────┐
│Prologu│ │Call Site│ │Boundary  │
│e      │ │Analyzer │ │Analyzer  │
│Matcher│ │(CALL/   │ │(ret+nop+ │
│       │ │ JMP)    │ │ aligned) │
└───┬───┘ └────┬────┘ └────┬─────┘
    │          │            │
    ▼          ▼            ▼
┌───────┐ ┌─────────┐ ┌──────────┐
│[]     │ │[]Call   │ │[]aligned │
│Prologue│ │SiteEdge │ │ entry VA │
└───┬───┘ └────┬────┘ └────┬─────┘
    │          │            │
    └──────────┴─────┬──────┘
                     ▼
            ┌───────────────┐
            │DetectFunctions│ ← Merge + score
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │  FP Filters   │ ← Anchor-range (intra-func JMPs)
            │               │   PLT section ranges
            └───────┬───────┘
                    ▼
            ┌───────────────┐
            │[]FunctionCand │
            │    idate      │
            └───────────────┘
```

## Limitations

- **No Symbol Information**: Works on stripped binaries but reports addresses only
- **Heuristic-Based**: PLT stubs and intra-function jump targets are filtered, but intra-function branches inside CRT code may still produce false positives when they land on aligned addresses with no surrounding anchor functions
- **Linear Disassembly**: Doesn't handle indirect jumps or computed addresses

## Dependencies

- **Go 1.25.7+**
- [`golang.org/x/arch`](https://pkg.go.dev/golang.org/x/arch) - x86 and ARM64 disassembler
- `debug/elf` (standard library) - ELF parser

## References

- [System V AMD64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Go x86 Assembler](https://pkg.go.dev/golang.org/x/arch/x86/x86asm)
- [Go ARM64 Assembler](https://pkg.go.dev/golang.org/x/arch/arm64/arm64asm)
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)

