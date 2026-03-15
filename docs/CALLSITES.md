# Call Site Analysis

This document provides detailed information about resurgo's call site analysis capabilities for function detection.

## Overview

Call site analysis identifies functions by detecting `CALL` and `JMP` instructions and extracting their target addresses. This approach complements prologue detection and works particularly well on:

- **Heavily optimized binaries** where compilers omit traditional prologues
- **Leaf functions** that don't set up stack frames
- **Naked functions** (e.g., interrupt handlers) without prologues
- **Compiler-agnostic analysis** since all compilers generate call instructions

## Call Site Types

### CALL Instructions

Function calls are the most reliable signal for function identification:

- **Direct calls** (`call rel32`)  - PC-relative addressing, high confidence
- **Indirect calls** (`call [addr]`)  - Memory addressing, high confidence if resolvable
- **Register calls** (`call rax`)  - Cannot be resolved statically, no confidence

**x86_64 encoding:**
```
E8 <rel32>              ; call rel32 (5 bytes)
FF /2 <ModR/M>          ; call r/m64 (indirect)
```

**ARM64 encoding:**
```
BL <imm26>              ; Branch with Link (4 bytes)
BLR <Xn>                ; Branch with Link to Register
```

### JMP Instructions

Jumps can indicate:
- **Tail calls** (optimization where a call becomes a jump)
- **Intra-function branches** (loops, branches within a function)
- **Trampolines** (jump tables, PLT entries)

**Unconditional jumps** have medium confidence (could be tail calls).
**Conditional jumps** have low confidence (usually intra-function branches).

**x86_64 encoding:**
```
E9 <rel32>              ; jmp rel32 (5 bytes)
EB <rel8>               ; jmp rel8 (2 bytes)
0F 8x <rel32>           ; conditional jmp (6 bytes)
```

**ARM64 encoding:**
```
B <imm26>               ; Branch (unconditional, 4 bytes)
B.cond <imm19>          ; Branch conditional (4 bytes)
BR <Xn>                 ; Branch to Register
```

## Addressing Modes

### PC-Relative (pc-relative)

Target address is calculated relative to the program counter:

**x86_64:**
```
target = sourceAddr + instructionLength + rel32
```

**ARM64:**
```
target = sourceAddr + signExtend(imm26 << 2)
```

**Characteristics:**
- Can be resolved statically
- Position-independent code (PIC) compatible
- Most common addressing mode

### Absolute (absolute)

Target address is specified directly in the instruction or memory:

**x86_64:**
```
call [0x401000]         ; Call through memory location
jmp [rip+0x2000]        ; RIP-relative indirect
```

**Characteristics:**
- Can be resolved if address is known
- Requires relocation in PIC
- Less common in modern binaries

### Register-Indirect (register-indirect)

Target address is stored in a register:

**x86_64:**
```
call rax                ; Call address in RAX
jmp [rbx+rcx*8]         ; Computed jump table
```

**ARM64:**
```
BLR X0                  ; Branch to address in X0
BR X1                   ; Jump to address in X1
```

**Characteristics:**
- Cannot be resolved statically
- Requires dynamic analysis or runtime tracing
- Common in virtual function calls, callbacks

## Confidence Scoring

Confidence indicates the likelihood that a detected edge points to a function entry:

| Level | Criteria | Typical Cases |
|-------|----------|---------------|
| **High** | Direct CALL with resolvable target | Function calls in normal code |
| **Medium** | Unconditional JMP with resolvable target | Tail call optimization |
| **Low** | Conditional JMP with resolvable target | Intra-function branches, loops |
| **None** | Register-indirect (unresolvable) | Virtual calls, callbacks |

### Confidence Escalation

When combined with prologue detection via `DetectFunctionsFromELF()`:
- Prologue + called -> **High confidence**
- Prologue only -> **Medium confidence**
- Called only -> **Medium confidence**
- Jump target only -> **Low to medium confidence**

## Comparison with Prologue Detection

| Aspect | Prologue Detection | Call Site Analysis |
|--------|-------------------|----------------------|
| **Coverage** | Functions with recognizable prologues | All called/jumped-to locations |
| **Optimization** | Fails on heavily optimized code | Works on all optimization levels |
| **Compiler** | Compiler-specific patterns | Compiler-agnostic |
| **False Positives** | Low (prologue patterns are distinctive) | Medium (jump targets may be internal) |
| **Leaf Functions** | May miss (no frame setup) | Catches if called |
| **Naked Functions** | Misses (no prologue) | Catches if called |

## Best Practices

### 1. Use Combined Analysis

For best results, use `DetectFunctionsFromELF()` which runs all detectors and filters:

```go
f, err := elf.Open("./myapp")
// ...
candidates, err := resurgo.DetectFunctionsFromELF(f)
```

This provides:
- **Highest confidence** for functions detected by both disassembly and CFI
- **Broader coverage** than either method alone
- **Source tracking** (which addresses call each function)

For raw bytes, combine the primitives manually:

```go
prologues, _ := resurgo.DetectPrologues(code, baseAddr, arch)
edges, _ := resurgo.DetectCallSites(code, baseAddr, arch)
```

### 2. Filter by Confidence

Focus on high-confidence edges for function identification:

```go
edges, _ := resurgo.DetectCallSites(code, baseAddr, arch)
for _, e := range edges {
    if e.Confidence == resurgo.ConfidenceHigh && e.Type == resurgo.CallSiteCall {
        // High-confidence function call
    }
}
```

### 3. Cross-Reference with Symbol Tables

If symbols are available, validate detected functions:

```go
// Validate that detected calls match known symbols
prologues, _ := resurgo.DetectPrologues(code, baseAddr, arch)
edges, _ := resurgo.DetectCallSites(code, baseAddr, arch)

prologueSet := make(map[uint64]bool)
for _, p := range prologues {
    prologueSet[p.Address] = true
}

for _, e := range edges {
    if e.Type == resurgo.CallSiteCall && prologueSet[e.TargetAddr] {
        // Both prologue AND called  - very high confidence
    }
}
```

### 4. Handle Edge Cases

Some patterns require special handling:

**PLT/GOT entries:**
```go
// PLT entries are jump trampolines to external functions
// Filter or handle separately based on section
```

**Tail calls:**
```go
// Unconditional jumps to different functions
// Check if target is outside current function scope
```

**Jump tables:**
```go
// Register-indirect jumps from switch statements
// Cannot be resolved statically, but can be identified by pattern
```

## Limitations

### Cannot Resolve Dynamically

- Virtual function calls (`call [vtable+offset]`)
- Function pointers stored in memory
- Computed addresses in registers
- Runtime-resolved PLT entries

### May Include False Positives

- Jumps to internal basic blocks (not function entries)
- Trampolines and thunks (PLT, GOT)
- Exception handlers (not typical functions)

### Architecture-Specific Constraints

**x86_64:**
- Variable-length instructions complicate linear disassembly
- ENDBR instructions (CET) are skipped automatically
- Some call encodings are ambiguous without context

**ARM64:**
- Fixed 4-byte instructions simplify analysis
- Conditional branches are common (low-confidence noise)
- BLR (register-indirect) cannot be resolved

## Examples

### Detecting Tail Calls

```go
edges, _ := resurgo.DetectCallSites(code, baseAddr, arch)
for _, e := range edges {
    if e.Type == resurgo.CallSiteJump &&
       e.Confidence == resurgo.ConfidenceMedium &&
       e.AddressMode == resurgo.AddressingModePCRelative {
        // Potential tail call
    }
}
```

### Building a Call Graph

```go
f, _ := elf.Open("./myapp")
candidates, _ := resurgo.DetectFunctionsFromELF(f)

// Create adjacency list
callGraph := make(map[uint64][]uint64)
for _, c := range candidates {
    for _, caller := range c.CalledFrom {
        callGraph[caller] = append(callGraph[caller], c.Address)
    }
}
```

### Identifying Entry Points

```go
f, _ := elf.Open("./myapp")
candidates, _ := resurgo.DetectFunctionsFromELF(f)

// Functions never called (potential entry points)
for _, c := range candidates {
    if len(c.CalledFrom) == 0 && c.DetectionType == resurgo.DetectionPrologueOnly {
        // Likely entry point or callback
    }
}
```

## References

- [x86_64 Instruction Set Reference](https://www.felixcloutier.com/x86/)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest)
- [System V AMD64 ABI - Control Transfer](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [Compiler Optimizations - Tail Call Elimination](https://en.wikipedia.org/wiki/Tail_call)
