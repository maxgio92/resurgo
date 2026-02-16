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

Prologues are one of the metadata that resurgo recovers about functions. They are detected by recognizing common instruction patterns at function entry points.

#### x86_64

On x86_64, the `CALL` instruction pushes the return address onto the stack automatically. RBP serves as the frame pointer (pointing to the base of the current stack frame) and RSP is the stack pointer. Functions typically save the caller's RBP and establish a new frame to create a linked list of stack frames that debuggers and unwinders can walk.

#### 1. Classic Frame Pointer Setup (`classic`)

```asm
push rbp        ; Save caller's frame pointer
mov rbp, rsp    ; Set up new frame pointer
```
`push rbp` saves the caller's frame pointer onto the stack. `mov rbp, rsp` then sets RBP to the current stack top, establishing the base of the new frame. Together they link this frame to the caller's frame, creating a chain that debuggers and stack unwinders traverse. This is the standard prologue in non-optimized builds (`-O0`) and code compiled with `-fno-omit-frame-pointer`.

#### 2. No-Frame-Pointer Function (`no-frame-pointer`)

```asm
sub rsp, 0x20   ; Allocate stack space directly
```
Optimizing compilers skip the frame pointer setup to free RBP as a general-purpose register, gaining a slight performance benefit. `sub rsp, imm` directly allocates stack space without establishing a frame chain. Stack unwinding relies on DWARF `.eh_frame` unwind tables instead. Common in optimized builds (`-O2`, `-O3`) or with `-fomit-frame-pointer`.

#### 3. Push-Only Prologue (`push-only`)

```asm
push rbx        ; Save callee-saved register
```
A push of any callee-saved register (rbx, rbp, r12–r15) at a function boundary without a subsequent `mov rbp, rsp`. When the compiler omits the frame pointer (`-fomit-frame-pointer`, the default at `-O2`), the first instruction of a function is often a push of whichever callee-saved register it needs, such as `push rbx` or `push r12`. No frame chain is established.

#### 4. LEA-Based Stack Allocation (`lea-based`)

```asm
lea rsp, [rsp-0x20]   ; Allocate using LEA instead of SUB
```
Achieves the same stack allocation as `sub rsp, 0x20` but without modifying the CPU flags register (RFLAGS). The compiler emits this when it needs to preserve flags across the stack allocation — for example, when a conditional branch depends on flags set before the prologue.

#### ARM64

Unlike x86_64, ARM64's `BL` (Branch with Link) instruction does not push the return address onto the stack — it stores it in **x30**, the link register (LR). The callee must explicitly save x30 to the stack if it needs to call other functions, otherwise the return address is overwritten. **x29** is the frame pointer (equivalent of RBP), used to build a chain of stack frames for unwinding.

ARM64 uses **STP** (Store Pair) to write two 64-bit registers to adjacent memory slots in a single instruction. Pre-index addressing (the `!` suffix) means the base register (SP) is decremented *before* the store takes place.

#### 1. STP Frame Pair (`stp-frame-pair`)

```asm
stp x29, x30, [sp, #-N]!   ; Save frame pointer and link register
mov x29, sp                  ; Set up new frame pointer
```
`stp x29, x30, [sp, #-N]!` decrements SP by N, then stores x29 (frame pointer) at `[SP]` and x30 (return address) at `[SP+8]` in one instruction. `mov x29, sp` then establishes the new frame pointer, creating a frame chain for stack unwinding. This is the standard AArch64 prologue emitted by C compilers (GCC, Clang) — the equivalent of x86's `push rbp; mov rbp, rsp`.

#### 2. STR LR Pre-Index (`str-lr-preindex`)

```asm
str x30, [sp, #-N]!   ; Save link register with stack allocation
```
Go's ARM64 calling convention differs from the standard AAPCS64. Instead of using STP to save both registers at once, Go saves x30 (the link register) alone with a pre-indexed store, then separately saves x29 with `STUR X29, [SP, #-8]` and sets up the frame pointer with `SUB X29, SP, #8`. This is the dominant prologue pattern in Go-compiled ARM64 binaries.

#### 3. Sub SP (`sub-sp`)

```asm
sub sp, sp, #N   ; Allocate stack space directly
```
Allocates stack space without saving any registers or setting up a frame pointer. The ARM64 equivalent of x86_64's no-frame-pointer pattern. Appears in leaf functions or when the compiler omits frame pointers.

#### 4. STP-Only (`stp-only`)

```asm
stp x29, x30, [sp, #-N]!   ; Save FP and LR only
```
The STP saves both x29 and x30 to the stack, but the function does not execute `mov x29, sp` afterward. The registers are preserved for restoration on return, but no frame chain is established — stack unwinding cannot follow frame pointers through this function.

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

