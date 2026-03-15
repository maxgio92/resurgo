package resurgo

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

const (
	// DetectionCFI is assigned to function candidates whose entry address was
	// read from DWARF Call Frame Information (CFI) rather than inferred by
	// disassembly heuristics. On ELF binaries the CFI is stored in .eh_frame.
	// These addresses are written by the compiler and are the highest-confidence
	// source available on stripped binaries.
	DetectionCFI DetectionType = "cfi"

	// .eh_frame FDE pointer-encoding constants (DW_EH_PE_*).
	//
	// The encoding byte is split into two nibbles:
	//   - lower nibble: data format (how the value is stored in the binary)
	//   - upper nibble: base (what the decoded value is relative to)
	//
	// Only the two encodings common on Linux x86-64 and ARM64 are handled.
	// Any other encoding causes the FDE to be skipped silently.
	ehPeAbsptr      = byte(0x00)             // absolute, pointer-sized (4 or 8 bytes)
	ehPeSdata4      = byte(0x0b)             // signed 32-bit integer
	ehPePcrel       = byte(0x10)             // PC-relative: add field's own VA to value
	ehPeOmit        = byte(0xff)             // field is not present; skip FDE
	ehPePcrelSdata4 = ehPePcrel | ehPeSdata4 // 0x1b — most common on Linux
)

// cieInfo holds the fields extracted from a CIE that are needed when
// decoding FDEs that reference it.
type cieInfo struct {
	fdeEncoding byte // DW_EH_PE_* byte from 'R' augmentation datum
}

// EhFrameDetector is a CandidateDetector that emits function candidates
// sourced from .eh_frame FDE records. Each candidate carries DetectionCFI
// and ConfidenceHigh. Returns an empty slice (no error) when .eh_frame is
// absent; the caller falls back to disassembly-only results.
func EhFrameDetector(f *elf.File) ([]FunctionCandidate, error) {
	fdeVAs, err := parseEhFrameEntries(f)
	if err != nil {
		return nil, fmt.Errorf("parse .eh_frame: %w", err)
	}
	candidates := make([]FunctionCandidate, 0, len(fdeVAs))
	for _, va := range fdeVAs {
		candidates = append(candidates, FunctionCandidate{
			Address:       va,
			DetectionType: DetectionCFI,
			Confidence:    ConfidenceHigh,
		})
	}
	return candidates, nil
}

// EhFrameFilter retains only candidates whose address is confirmed by an FDE
// record in .eh_frame, upgrading their confidence to ConfidenceHigh.
// When .eh_frame is absent the slice is returned unchanged.
func EhFrameFilter(candidates []FunctionCandidate, f *elf.File) ([]FunctionCandidate, error) {
	fdeVAs, err := parseEhFrameEntries(f)
	if err != nil {
		return nil, fmt.Errorf("parse .eh_frame: %w", err)
	}
	if len(fdeVAs) == 0 {
		return candidates, nil
	}

	fdeSet := make(map[uint64]struct{}, len(fdeVAs))
	for _, va := range fdeVAs {
		fdeSet[va] = struct{}{}
	}

	// Keep only candidates confirmed by an FDE.
	filtered := candidates[:0]
	for _, c := range candidates {
		if _, ok := fdeSet[c.Address]; ok {
			c.Confidence = ConfidenceHigh
			filtered = append(filtered, c)
		}
	}
	return filtered, nil
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
			enc := data[off] // encoding byte tells us the pointer format
			off++
			var err error
			// Skip the pointer value — its size depends on enc and ptrSize.
			// We only need to advance past it to reach the 'R' field.
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

// decodeFDEInitialLocation decodes the initial_location field of an FDE.
// data is the raw .eh_frame section bytes; off is the byte offset of the
// field within data; secAddr is the section's load address, used to compute
// the field's own virtual address for PC-relative encodings.
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
		return 0, false // field absent; FDE has no initial_location
	}

	fieldVA := secAddr + uint64(off) // VA of initial_location; base for PC-relative decoding

	switch enc {
	case ehPeAbsptr:
		if ptrSize == 8 {
			if off+8 > len(data) {
				return 0, false // truncated 64-bit pointer
			}
			return bo.Uint64(data[off : off+8]), true // 64-bit absolute VA
		}
		if off+4 > len(data) {
			return 0, false // truncated 32-bit pointer
		}
		return uint64(bo.Uint32(data[off : off+4])), true // 32-bit absolute VA

	case ehPePcrelSdata4:
		if off+4 > len(data) {
			return 0, false // truncated PC-relative value
		}
		rel := int32(bo.Uint32(data[off : off+4]))
		return fieldVA + uint64(int64(rel)), true // PC-relative: rel + VA of the initial_location field itself

	default:
		return 0, false // unsupported encoding; skip FDE silently
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
		// byt&0x7f strips the continuation bit (MSB), leaving 7 payload bits.
		// <<shift places them at the right position in the accumulator:
		// first byte at bits 0-6, second at 7-13, and so on.
		// |= merges without disturbing the bits placed by previous iterations.
		val |= uint64(byt&0x7f) << shift
		shift += 7
		if byt&0x80 == 0 { // MSB clear = last byte
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
		// Same accumulation as ULEB128: strip MSB, place 7 bits at position shift.
		val |= int64(byt&0x7f) << shift
		shift += 7
		if byt&0x80 == 0 { // MSB clear = last byte
			// bit 6 of the last byte is the sign bit of the 7-bit group.
			// If set, the value is negative: fill all bits above shift with 1s.
			if shift < 64 && byt&0x40 != 0 {
				val |= ^int64(0) << shift
			}
			return val, i - off + 1
		}
	}
	return 0, -1
}
