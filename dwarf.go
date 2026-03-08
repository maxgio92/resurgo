package resurgo

import (
	"cmp"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"slices"
)

// DetectionCFI is assigned to function candidates whose entry address was
// read from DWARF Call Frame Information (CFI) rather than inferred by
// disassembly heuristics. On ELF binaries the CFI is stored in .eh_frame.
// These addresses are written by the compiler and are the highest-confidence
// source available on stripped binaries.
const DetectionCFI DetectionType = "cfi"

// ehFrameFilter parses .eh_frame and applies the FDE whitelist to the
// candidate slice. See applyEhFrame for the merge logic.
func ehFrameFilter(cs []FunctionCandidate, f *elf.File) ([]FunctionCandidate, error) {
	fdeVAs, err := parseEhFrameEntries(f)
	if err != nil {
		return nil, fmt.Errorf("parse .eh_frame: %w", err)
	}
	return applyEhFrame(cs, fdeVAs), nil
}

// applyEhFrame applies .eh_frame FDE data to the candidate slice.
// When fdeVAs is empty it returns candidates unchanged (fallback for binaries
// without .eh_frame). Otherwise it:
//   - drops candidates whose address is not confirmed by any FDE
//   - appends pure FDE hits (functions invisible to disassembly heuristics)
//   - re-sorts the result by address
func applyEhFrame(candidates []FunctionCandidate, fdeVAs []uint64) []FunctionCandidate {
	if len(fdeVAs) == 0 {
		return candidates
	}

	fdeSet := make(map[uint64]struct{}, len(fdeVAs))
	for _, va := range fdeVAs {
		fdeSet[va] = struct{}{}
	}

	// Keep only candidates confirmed by an FDE.
	filtered := candidates[:0]
	for _, c := range candidates {
		if _, ok := fdeSet[c.Address]; ok {
			filtered = append(filtered, c)
		}
	}
	candidates = filtered

	// Append FDE-only hits not already found by disassembly.
	disasmSet := make(map[uint64]struct{}, len(candidates))
	for _, c := range candidates {
		disasmSet[c.Address] = struct{}{}
	}
	for _, va := range fdeVAs {
		if _, ok := disasmSet[va]; !ok {
			candidates = append(candidates, FunctionCandidate{
				Address:       va,
				DetectionType: DetectionCFI,
				Confidence:    ConfidenceHigh,
			})
		}
	}

	slices.SortFunc(candidates, func(a, b FunctionCandidate) int {
		return cmp.Compare(a.Address, b.Address)
	})
	return candidates
}

// parseEhFrameEntries parses the .eh_frame section of f and returns the
// absolute virtual address of every FDE's initial_location field.
// These addresses are function entry points written by the compiler.
//
// Returns nil (no error) if .eh_frame is absent — the caller treats this
// as a signal to fall back to the disassembly-only pipeline.
// Returns an error only for I/O failures; malformed records are skipped.
func parseEhFrameEntries(f *elf.File) ([]uint64, error) {
	sec := f.Section(".eh_frame")
	if sec == nil {
		return nil, nil
	}

	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .eh_frame: %w", err)
	}

	bo := f.ByteOrder
	secAddr := sec.Addr

	// ptrSize drives both absptr decoding and CIE_id back-reference arithmetic.
	ptrSize := 4
	if f.Class == elf.ELFCLASS64 {
		ptrSize = 8
	}

	// cies maps the byte offset of each CIE record's start within data
	// to the parsed cieInfo for that CIE.
	cies := make(map[int]cieInfo)
	var entries []uint64

	off := 0
	for off < len(data) {
		recStart := off

		if off+4 > len(data) {
			break
		}
		length := int(bo.Uint32(data[off : off+4]))
		off += 4

		if length == 0 {
			break // zero-length record signals end of section
		}
		if length == 0xffffffff {
			// 64-bit DWARF extended form: real length follows as uint64.
			// Rare in .eh_frame; skip the entire record.
			if off+8 > len(data) {
				break
			}
			length64 := bo.Uint64(data[off : off+8])
			off += 8 + int(length64)
			continue
		}

		recEnd := off + length
		if recEnd > len(data) {
			break // truncated section; stop
		}

		if off+4 > recEnd {
			// Record too short to contain CIE_id; skip.
			off = recEnd
			continue
		}
		cieID := bo.Uint32(data[off : off+4])
		off += 4

		if cieID == 0 {
			// CIE: parse and store so FDEs can look it up by offset.
			cie, err := parseCIE(data, off, recEnd, ptrSize)
			if err != nil {
				// Malformed CIE — skip; FDEs referencing it will also be skipped.
				off = recEnd
				continue
			}
			cies[recStart] = cie
		} else {
			// FDE: CIE_id is a byte offset from the CIE_id field's own
			// position back to the start of the referenced CIE record.
			cieFieldOff := off - 4
			cieOff := cieFieldOff - int(cieID)

			cie, ok := cies[cieOff]
			if !ok {
				// Referenced CIE not seen yet or malformed reference; skip FDE.
				off = recEnd
				continue
			}

			// off now points at initial_location, the first field of the FDE body.
			// secAddr resolves PC-relative encodings; fdeEncoding was extracted
			// from the CIE's 'R' augmentation datum; bo and ptrSize are the
			// ELF-level byte order and pointer width.
			va, ok := decodeFDEInitialLocation(
				data, off, secAddr, cie.fdeEncoding, bo, ptrSize,
			)
			if ok {
				entries = append(entries, va)
			}
		}

		off = recEnd
	}

	return entries, nil
}

// cieInfo holds the fields extracted from a CIE that are needed when
// decoding FDEs that reference it.
type cieInfo struct {
	fdeEncoding byte // DW_EH_PE_* byte from 'R' augmentation datum
}

// parseCIE parses the body of a CIE record (the bytes after CIE_id, up to
// end) and returns the extracted cieInfo. The default fdeEncoding is
// ehPeAbsptr (absolute pointer) when no 'R' augmentation datum is present.
func parseCIE(data []byte, off, end, ptrSize int) (cieInfo, error) {
	info := cieInfo{fdeEncoding: ehPeAbsptr}

	if off >= end {
		return info, fmt.Errorf("empty CIE body")
	}

	// Version (1 byte) — not used but must be consumed.
	off++

	// Augmentation string: null-terminated ASCII.
	augStart := off
	for off < end && data[off] != 0 {
		off++
	}
	if off >= end {
		return info, fmt.Errorf("unterminated CIE augmentation string")
	}
	augStr := string(data[augStart:off])
	off++ // skip null terminator

	// Code alignment factor (ULEB128).
	_, n := readULEB128(data, off)
	if n < 0 {
		return info, fmt.Errorf("truncated code alignment factor")
	}
	off += n

	// Data alignment factor (SLEB128).
	_, n2 := readSLEB128(data, off)
	if n2 < 0 {
		return info, fmt.Errorf("truncated data alignment factor")
	}
	off += n2

	// Return address register.
	// DWARF2 encodes this as a single byte; DWARF3+ uses ULEB128.
	// Since register numbers are always < 128, ULEB128 handles both
	// cases identically (a byte with MSB=0 is a valid 1-byte ULEB128).
	_, n3 := readULEB128(data, off)
	if n3 < 0 {
		return info, fmt.Errorf("truncated return address register")
	}
	off += n3

	// Augmentation data block — present only when augStr starts with 'z'.
	if len(augStr) == 0 || augStr[0] != 'z' {
		return info, nil
	}

	augDataLen, n4 := readULEB128(data, off)
	if n4 < 0 {
		return info, fmt.Errorf("truncated augmentation data length")
	}
	off += n4
	augDataEnd := off + int(augDataLen)

	// Process each augmentation character after 'z'.
	for _, ch := range augStr[1:] {
		if off >= augDataEnd {
			break
		}
		switch ch {
		case 'L':
			// LSDA encoding byte — 1 byte, not needed.
			off++
		case 'P':
			// Personality routine: 1-byte encoding + the pointer itself.
			if off >= augDataEnd {
				break
			}
			enc := data[off]
			off++
			var err error
			off, err = skipEncodedPointer(data, off, enc, ptrSize)
			if err != nil {
				return info, fmt.Errorf("skip personality pointer: %w", err)
			}
		case 'R':
			// FDE pointer encoding byte — this is what we came for.
			if off < augDataEnd {
				info.fdeEncoding = data[off]
				off++
			}
		}
	}

	return info, nil
}

// .eh_frame FDE pointer-encoding constants (DW_EH_PE_*).
//
// The encoding byte is split into two nibbles:
//   - lower nibble: data format (how the value is stored in the binary)
//   - upper nibble: base (what the decoded value is relative to)
//
// Only the two encodings common on Linux x86-64 and ARM64 are handled.
// Any other encoding causes the FDE to be skipped silently.
const (
	ehPeAbsptr      = byte(0x00) // absolute, pointer-sized (4 or 8 bytes)
	ehPeSdata4      = byte(0x0b) // signed 32-bit integer
	ehPePcrel       = byte(0x10) // PC-relative: add field's own VA to value
	ehPeOmit        = byte(0xff) // field is not present; skip FDE
	ehPePcrelSdata4 = ehPePcrel | ehPeSdata4 // 0x1b — most common on Linux
)

// decodeFDEInitialLocation decodes the initial_location field of an FDE.
// off is the byte offset of the field within data; secAddr is the section's
// load address, used to compute the field's own virtual address for
// PC-relative encodings.
//
// Returns the absolute virtual address and true on success, or 0, false if
// the encoding is unsupported or the data is truncated.
func decodeFDEInitialLocation(
	data []byte,
	off int,
	secAddr uint64,
	enc byte,
	bo binary.ByteOrder,
	ptrSize int,
) (uint64, bool) {
	if enc == ehPeOmit {
		return 0, false
	}

	// fieldVA is the virtual address of this field in the loaded binary.
	// Required for PC-relative decoding.
	fieldVA := secAddr + uint64(off)

	switch enc {
	case ehPeAbsptr:
		if ptrSize == 8 {
			if off+8 > len(data) {
				return 0, false
			}
			return bo.Uint64(data[off : off+8]), true
		}
		if off+4 > len(data) {
			return 0, false
		}
		return uint64(bo.Uint32(data[off : off+4])), true

	case ehPePcrelSdata4:
		if off+4 > len(data) {
			return 0, false
		}
		rel := int32(bo.Uint32(data[off : off+4]))
		return fieldVA + uint64(int64(rel)), true

	default:
		// Unsupported encoding — skip silently.
		return 0, false
	}
}

// skipEncodedPointer advances off past a pointer encoded with enc.
// Used to skip the personality-routine pointer in CIE augmentation data
// so that the 'R' FDE-encoding byte can be reached.
func skipEncodedPointer(b []byte, off int, enc byte, ptrSize int) (int, error) {
	switch enc & 0x0f { // format is in the lower nibble
	case 0x00: // absptr — pointer-sized
		return off + ptrSize, nil
	case 0x02: // udata2
		return off + 2, nil
	case 0x03: // udata4
		return off + 4, nil
	case 0x04: // udata8
		return off + 8, nil
	case 0x09: // sleb128
		_, n := readSLEB128(b, off)
		if n < 0 {
			return 0, fmt.Errorf("truncated sleb128 at offset %d", off)
		}
		return off + n, nil
	case 0x0a: // sdata2
		return off + 2, nil
	case 0x0b: // sdata4
		return off + 4, nil
	case 0x0c: // sdata8
		return off + 8, nil
	default:
		return 0, fmt.Errorf("unsupported pointer encoding 0x%02x", enc)
	}
}

// readULEB128 decodes an unsigned LEB128 integer from b at offset off.
// Returns the decoded value and the number of bytes consumed.
// Returns n == -1 if the data is truncated.
func readULEB128(b []byte, off int) (val uint64, n int) {
	var shift uint
	for i := off; i < len(b); i++ {
		byt := b[i]
		val |= uint64(byt&0x7f) << shift
		shift += 7
		if byt&0x80 == 0 {
			return val, i - off + 1
		}
	}
	return 0, -1
}

// readSLEB128 decodes a signed LEB128 integer from b at offset off.
// Returns the decoded value and the number of bytes consumed.
// Returns n == -1 if the data is truncated.
func readSLEB128(b []byte, off int) (val int64, n int) {
	var shift uint
	for i := off; i < len(b); i++ {
		byt := b[i]
		val |= int64(byt&0x7f) << shift
		shift += 7
		if byt&0x80 == 0 {
			// Sign-extend if the sign bit of the last group is set.
			if shift < 64 && byt&0x40 != 0 {
				val |= ^int64(0) << shift
			}
			return val, i - off + 1
		}
	}
	return 0, -1
}
