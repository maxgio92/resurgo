# resurgo

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
- `classic` — push rbp; mov rbp, rsp
- `no-frame-pointer` — sub rsp, imm
- `push-only` — push <callee-saved-reg>
- `lea-based` — lea rsp, [rsp-imm]

**ARM64:**
- `stp-frame-pair` — stp x29, x30, [sp, #-N]!; mov x29, sp
- `str-lr-preindex` — str x30, [sp, #-N]!
- `sub-sp` — sub sp, sp, #N
- `stp-only` — stp x29, x30, [sp, #-N]!

For detailed explanations of each pattern, see [docs/PROLOGUES.md](docs/PROLOGUES.md).

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

## API Reference

**Functions:**

```go
// Core detection — works on raw machine code bytes, no I/O.
// arch selects architecture-specific detection logic.
func DetectPrologues(code []byte, baseAddr uint64, arch Arch) ([]Prologue, error)

// Convenience wrapper — parses ELF from the reader, extracts .text, calls DetectPrologues.
// Architecture is inferred from the ELF header.
func DetectProloguesFromELF(r io.ReaderAt) ([]Prologue, error)
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
         ▼
┌─────────────────┐
│ Pattern Matcher │ ← Prologue detection logic
│   (insns seq)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  []Prologue     │
│ (addr + type)   │
└─────────────────┘
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

