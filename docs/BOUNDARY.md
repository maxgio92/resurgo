# Boundary Analysis

This document describes resurgo's boundary analysis strategy for function entry detection.

## Overview

Boundary analysis finds function entry points by reading the structural gap compilers emit between adjacent functions. Unlike prologue detection (which asks "what does this function start with?") and call-site analysis (which asks "who calls this function?"), boundary analysis asks "did the compiler leave an alignment gap here, signalling a new function is about to start?"

This strategy recovers functions that are invisible to the other two approaches:

- **Pure-leaf functions**: make no calls, so the compiler omits frame setup entirely. No prologue, no call-site edges.
- **Compile-time-evaluated functions**: a function may exist in the binary with external linkage but its callers have been inlined or its result computed at compile time (e.g. `factorial(5)` folded to `120`). No call sites are ever emitted.

## The pattern

Compilers lay out functions one after another in the `.text` section and align each entry to a 16-byte boundary for CPU fetch efficiency. When the previous function ends before that boundary, the compiler fills the gap with NOP instructions — dead bytes that will never be executed, placed purely to reach the alignment point.

```
function A:
    ...
    ret                    ; function A ends here
    nop nop nop ...        ; compiler fills dead space
<16-byte aligned address>  ; function B starts here  ← detector fires
function B:
    ...
```

The NOP fill is the key signal. A compiler only emits it when it knows a new function is coming. It does not insert NOP fill between two live code paths of the same function — those paths are connected by jumps and require no alignment padding between them.

## Terminators

The detector scans `.text` for instructions that end a function's code path and are followed by NOP padding:

### `RET` / `LRET` (primary)

A return instruction pops the return address from the stack and transfers control back to the caller. Nothing falls through to the next byte. Any NOP fill after a `RET` was placed there by the compiler to align the next function.

### Backward unconditional `JMP` (secondary)

An unconditional jump that targets an address **before** the jump instruction itself is almost certainly a tail call — the compiler replaced `call baz; ret` with `jmp baz`, transferring control to a sibling or external function. After this jump, the compiler emits NOP fill for the same reason as after `RET`.

Forward unconditional `JMP`s are **excluded** as terminators. Inside a function, GCC and Clang emit forward `JMP`s for loop exits, tail merges, and switch fall-throughs, and they also align the targets of these jumps (`-falign-jumps`). This produces the same byte pattern — `jmp → nop fill → aligned address` — but the aligned address is an internal branch target, not a function entry.

## Filters

Two post-match filters prevent the most common intra-function false positives:

### 1. Require at least one padding byte

A bare `RET` immediately followed by a non-NOP instruction (e.g. the base case of a function reached by a conditional branch) does not indicate a function boundary. The padding must actually be present.

### 2. Discard if boundary instruction is `RET`/`LRET`

An inlined base-case return path can land on a 16-byte aligned address:

```asm
; inside factorial
11ad:  ret            ; end of loop path
11ae:  xchg %ax, %ax  ; 2-byte NOP (alignment fill)
11b0:  ret            ; base-case return  ← 16-byte aligned
```

Here `11b0` is the target of a conditional branch (`jle 11b0`) within the same function. A function starting with `RET` would be a no-op stub — this exists in practice only as a deliberate compiler-generated trampoline, not as a user-written function. Discarding these eliminates this false positive class entirely.

## Confidence

Candidates from boundary analysis receive `ConfidenceLow`. The pattern is reliable at identifying that *something* starts at an aligned boundary, but it cannot distinguish user functions from compiler-injected runtime scaffolding (CRT functions like `_start`, `frame_dummy`, `__do_global_dtors_aux`) that happen to follow the same layout rules.

When boundary analysis fires on an address that is also a call-site target or has a recognised prologue, the existing prologue/call-site confidence takes precedence (boundary analysis does not add a new candidate in that case).

The three-strategy confidence model:

| Strategies that fired | Confidence |
|---|---|
| Boundary only | `low` |
| Prologue only | `medium` |
| Call-site only | `medium` |
| Prologue + call-site | `high` |

## Architecture support

Boundary analysis is currently implemented for **AMD64** only. The AMD64 NOP encoding family (`0x90`, multi-byte `0x0F 0x1F ...`, `data16 cs nopw`, `xchg %ax, %ax`) is well-defined and reliably distinguishable from code.

ARM64 uses fixed 4-byte instructions, making alignment padding trivially identifiable (the canonical ARM64 NOP is `0xd503201f`). ARM64 support is tracked as a future extension.

## Limitations

- **First function in a chain**: if function B has no recognisable predecessor (e.g. it is the very first function in `.text`, or the function before it ends with an unresolvable indirect jump), the chain breaks and boundary analysis cannot detect it.
- **CRT noise**: `_start`, `frame_dummy`, `__do_global_dtors_aux` and similar linker-injected functions follow the same alignment convention and appear as `ConfidenceLow` candidates. In real-world binaries with many user functions they represent a small fraction of total candidates.
- **Non-standard alignment**: binaries compiled with `-falign-functions=1` (no alignment) or unusual linker scripts do not emit NOP fill, making this strategy ineffective.

## References

- [System V AMD64 ABI — Function Alignment](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [GCC `-falign-functions` option](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [Intel 64 and IA-32 Architectures Software Developer Manuals — NOP encodings](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
