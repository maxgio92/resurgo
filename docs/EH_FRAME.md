# EH Frame Detection

This document describes resurgo's `.eh_frame`-based strategy for function entry detection.

## Overview

**CFI (Call Frame Information)** is a DWARF standard for describing how to
unwind the call stack at any point in a program, enabling `backtrace()`,
exception handling, and debuggers. `.eh_frame` is the ELF section that stores
CFI data as a sequence of **CIE** and **FDE** records.

On Linux, the compiler emits `-fasynchronous-unwind-tables` by default on
x86-64 and ARM64. This causes one FDE to be generated for every function,
unconditionally - including leaf functions, cold paths, and internal helpers
that carry no other detectable signal (no prologue, never called directly).

Each FDE contains the function's precise entry address (`initial_location`).
Critically, `.eh_frame` survives `strip --strip-all` because the OS needs it
for signal delivery and stack unwinding at runtime. It is present in
production stripped binaries where `.symtab` and `.debug_*` are long gone.

This makes `.eh_frame` the highest-confidence detection source in resurgo: the
addresses it provides were written by the compiler, not inferred by heuristics.

## Record structure

The `.eh_frame` section is a flat sequence of records, back to back in memory.
Every record starts with two fixed fields:

- **`length` (4 bytes):** how many bytes follow, not counting `length` itself.
  `0` is a terminator - stop parsing. `0xffffffff` signals the 64-bit extended
  form (the real length is in the next 8 bytes); this is rare and skipped for
  now.
- **`CIE_id` (4 bytes):** `0` means this record is a CIE. Any other value
  means this record is an FDE, and the value is the byte offset from the
  current position back to the associated CIE.

Advance to the next record by jumping `length + 4` bytes from the start of the
current record.

### CIE - Common Information Entry

A CIE is the shared header referenced by one or more FDEs. It avoids
repeating common metadata in every FDE. Its body contains:

1. **Version** (1 byte)
2. **Augmentation string** (null-terminated ASCII) - an extensibility hook.
   The base DWARF spec defines a fixed field set, but `.eh_frame` needed extra
   data for Linux runtime unwinding and C++ exception handling. Rather than
   bumping the format version, the spec added the augmentation string: each
   character signals an extra field. Common characters:
   - `'z'` - an augmentation data block follows (with a ULEB128 length prefix)
   - `'R'` - FDE pointer encoding byte (how `initial_location` is encoded)
   - `'P'` - personality routine pointer (C++ exception handler)
   - `'L'` - LSDA (Language Specific Data Area) encoding byte
3. **Code alignment factor** (ULEB128)
4. **Data alignment factor** (SLEB128)
5. **Return address register** (1 byte)
6. **Augmentation data block** (only if `'z'` is in the augmentation string):
   read its length (ULEB128), then process one byte per augmentation character
   after `'z'`: skip `'L'` (1 byte), skip `'P'` (pointer), and for `'R'`
   **save the byte** - it is the FDE pointer encoding for all FDEs that
   reference this CIE.

### FDE - Frame Description Entry

An FDE covers one contiguous code range (one function, or an inlined region).
Its body starts with:

- **`initial_location`** - the entry address of the covered range, encoded per
  the FDE pointer encoding byte saved from its CIE.
- **`address_range`** - the size of the covered range (same encoding, unsigned).
- Augmentation data and CFI opcodes (not needed for entry detection; skipped).

## ULEB128 and SLEB128

Several CIE fields use variable-length integer encodings to avoid wasting space
on fixed-width integers. Each byte contributes **7 bits** of data; the MSB is
a continuation flag (`1` = more bytes follow, `0` = last byte). The "128" in
the name reflects that each byte carries one base-128 digit (2^7 = 128).
ULEB128 is unsigned; SLEB128 is signed (the last byte is sign-extended from
bit 6).

Small values (< 128) cost 1 byte. A 64-bit value costs at most 10 bytes
(ceil(64/7)). In practice DWARF alignment factors and register numbers are
almost always < 128, so the savings are real.

## FDE pointer encoding (`DW_EH_PE_*`)

The FDE pointer encoding byte is split into two nibbles (a nibble is 4 bits,
half a byte):

- **Upper nibble** - base: where the value is relative to.
  `0x0_` = absolute; `0x1_` = PC-relative (relative to the address of the
  field in the loaded binary); other bases exist but are uncommon.
- **Lower nibble** - format: how the value is stored.
  `0x_0` = raw pointer (pointer-sized); `0x_b` = signed 32-bit (`sdata4`);
  other formats exist.

The two common encodings on Linux:

| Encoding byte | Name | Decoding |
|---|---|---|
| `0x00` | `DW_EH_PE_absptr` | raw `uint64` (or `uint32` on 32-bit) |
| `0x1b` | `DW_EH_PE_pcrel\|sdata4` | `int32` + address of the field in the loaded binary |

For `0x1b`, the reference address is
`section.Addr + offset_of_field_within_section`.

Anything else: skip the FDE silently (log at debug level, do not fail).

## Core function: `parseEhFrameEntries`

```go
// parseEhFrameEntries parses the .eh_frame section of f and returns the
// absolute virtual address of every FDE's initial_location field.
// These addresses are function entry points written by the compiler.
//
// Returns nil (no error) if .eh_frame is absent - the caller treats this
// as a signal to fall back to the disassembly-only pipeline.
// Returns an error only for genuinely malformed data.
func parseEhFrameEntries(f *elf.File) ([]uint64, error)
```

Walking algorithm:

1. Find the `.eh_frame` section. If absent, return `nil, nil`.
2. Read all section bytes; record the section's load address (`sec.Addr`).
3. Walk records in a loop, tracking `offset` within the section bytes:
   a. Read `length` (4 bytes, host byte order from `f.ByteOrder`). Stop if `0`.
      Skip if `0xffffffff` (64-bit form).
   b. Read `CIE_id` (4 bytes).
   c. If `CIE_id == 0`: parse the CIE, extract and store the FDE encoding byte,
      keyed by the CIE's offset in the section.
   d. If `CIE_id != 0`: look up the FDE encoding byte from the referenced CIE.
      Decode `initial_location`; append the resolved VA to results.
   e. Advance `offset` by `length + 4`.
4. Return the collected VA slice.

## Integration in `DetectFunctionsFromELF`

After opening the ELF and before returning:

1. Call `parseEhFrameEntries(f)`.
2. If it returns entries, build `fdeSet map[uint64]struct{}`.
3. Run `filterByEhFrame(candidates, fdeSet)`: keep only disassembly candidates
   whose address appears in `fdeSet`. This eliminates FP noise.
4. Emit one additional `FunctionCandidate{DetectionType: DetectionEhFrame}`
   for each FDE VA not already covered by a disassembly candidate (pure FDE
   hits - functions invisible to all heuristics).
5. If `parseEhFrameEntries` returns nil: skip all of the above; return the
   current disassembly pipeline output unchanged.

PLT filtering still runs before this step.

## Confidence and detection type

Candidates sourced from `.eh_frame` receive `DetectionEhFrame`. Because FDE
entries are compiler-generated and not inferred, they are treated as the
highest-confidence source. Disassembly candidates confirmed by an FDE may be
promoted or merged with the richer disassembly metadata.

## Limitations

- **Not universal:** Go binaries use `.gopclntab` instead of `.eh_frame`.
  ARM bare-metal uses `.ARM.exidx`/`.ARM.extab`. Hand-written assembly only
  has FDE entries if the programmer adds `.cfi_*` directives.
- **Aggressive stripping:** `strip -R .eh_frame` removes the section entirely.
  The fallback path handles this transparently.
- **ELF-specific:** this strategy lives in `DetectFunctionsFromELF` only.
  The format-agnostic `DetectFunctions` is not affected.
- **Inlined regions:** a single function can produce multiple FDEs if the
  compiler splits it into hot/cold regions. The current parser emits one
  candidate per FDE; deduplication by VA handles this correctly.

## References

- [DWARF4 Specification - Section 6.4: Call Frame Information](https://dwarfstd.org/doc/DWARF4.pdf)
- [Linux Standard Base - .eh_frame sections](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
- [System V AMD64 ABI - Unwind Library Interface](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
