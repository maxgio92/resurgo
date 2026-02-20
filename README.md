# resurgo

[![CI](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgio92/resurgo/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/maxgio92/resurgo.svg)](https://pkg.go.dev/github.com/maxgio92/resurgo)
[![GitHub Tag](https://img.shields.io/github/v/tag/maxgio92/resurgo)](https://github.com/maxgio92/resurgo/tags)

A Go library for static function recovery from executable binaries.

It works with raw bytes from any binary format as well as parsing ELF files.

## Features

- **Prologue-Based Detection**: Recognizes common function entry patterns by instruction analysis
- **Format-Agnostic Core**: Works on raw machine code bytes from any binary format
- **ELF Convenience Wrapper**: Built-in support for parsing ELF executables
- **Pattern Classification**: Labels detected prologues by type

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

### Call site analysis

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

## Usage

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

### Call site analysis

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

// Convenience wrapper  - parses ELF from the reader, extracts .text, calls DetectFunctions.
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
    DetectionBoth         DetectionType = "both" // Prologue + called/jumped to
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
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────────┐
│Prologue│ │ Call Site  │
│Matcher │ │  Analyzer  │
│(seq)   │ │(CALL/JMP)  │
└───┬────┘ └─────┬──────┘
    │             │
    ▼             ▼
┌────────┐ ┌────────────┐
│[]Prolog│ │[]CallSite │
│  ue    │ │  Edge      │
└───┬────┘ └─────┬──────┘
    │             │
    └──────┬──────┘
           ▼
   ┌───────────────┐
   │DetectFunctions│ ← Merge + score
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │[]FunctionCand │
   │    idate      │
   └───────────────┘
```

## Limitations

- **No Symbol Information**: Works on stripped binaries but reports addresses only
- **Heuristic-Based**: May have false positives in data sections or inline data
- **Linear Disassembly**: Doesn't handle indirect jumps or computed addresses

## Dependencies

- **Go 1.21+**
- [`golang.org/x/arch`](https://pkg.go.dev/golang.org/x/arch) - x86 and ARM64 disassembler
- `debug/elf` (standard library) - ELF parser

## References

- [System V AMD64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Go x86 Assembler](https://pkg.go.dev/golang.org/x/arch/x86/x86asm)
- [Go ARM64 Assembler](https://pkg.go.dev/golang.org/x/arch/arm64/arm64asm)
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)

