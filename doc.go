// Package resurgo detects function prologues from raw machine code or ELF
// binaries using instruction-level disassembly.
//
// It recognizes several common prologue patterns including classic frame pointer
// setup (push rbp; mov rbp, rsp), no-frame-pointer functions (sub rsp, imm),
// push-only prologues, and LEA-based stack allocation.
//
// Use [DetectPrologues] to analyze raw bytes directly, or
// [DetectProloguesFromELF] to extract and analyze the .text section of an ELF
// binary.
package resurgo
