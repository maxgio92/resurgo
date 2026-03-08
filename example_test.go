package resurgo_test

import (
	"fmt"
	"log"
	"os"

	"github.com/maxgio92/resurgo"
)

func ExampleDetectPrologues() {
	// x86-64 machine code: nop; push rbp; mov rbp, rsp
	code := []byte{0x90, 0x55, 0x48, 0x89, 0xe5}
	prologues, err := resurgo.DetectPrologues(code, 0x1000, resurgo.ArchAMD64)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range prologues {
		fmt.Printf("[%s] 0x%x: %s\n", p.Type, p.Address, p.Instructions)
	}
	// Output:
	// [classic] 0x1001: push rbp; mov rbp, rsp
}

func ExampleDetectProloguesFromELF() {
	f, err := os.Open("/usr/bin/ls")
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

func ExampleDetectCallSites() {
	// x86-64 machine code: call $+0x20 (E8 1B 00 00 00)
	// At address 0x1000, calls target at 0x1000 + 5 + 0x1B = 0x1020
	code := []byte{0xE8, 0x1B, 0x00, 0x00, 0x00}
	edges, err := resurgo.DetectCallSites(code, 0x1000, resurgo.ArchAMD64)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range edges {
		fmt.Printf("[%s] 0x%x -> 0x%x (%s, %s)\n",
			e.Type, e.SourceAddr, e.TargetAddr, e.AddressMode, e.Confidence)
	}
	// Output:
	// [call] 0x1000 -> 0x1020 (pc-relative, high)
}

func ExampleDetectCallSitesFromELF() {
	f, err := os.Open("/usr/bin/ls")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	edges, err := resurgo.DetectCallSitesFromELF(f)
	if err != nil {
		log.Fatal(err)
	}

	// Show first 5 high-confidence call edges
	count := 0
	for _, e := range edges {
		if e.Type == resurgo.CallSiteCall && e.Confidence == resurgo.ConfidenceHigh {
			fmt.Printf("[%s] 0x%x -> 0x%x (%s)\n",
				e.Type, e.SourceAddr, e.TargetAddr, e.AddressMode)
			count++
			if count >= 5 {
				break
			}
		}
	}
}

func ExampleDetectFunctions() {
	// x86-64 code with prologue and call:
	// 0x1000: push rbp; mov rbp, rsp
	// 0x1004: call 0x1020
	// ...
	// 0x1020: push rbp; mov rbp, rsp (called function)
	code := make([]byte, 0x30)
	code[0x00] = 0x55 // push rbp
	code[0x01] = 0x48 // mov rbp, rsp
	code[0x02] = 0x89
	code[0x03] = 0xe5
	code[0x04] = 0xE8 // call
	code[0x05] = 0x17 // rel32 = 0x17
	code[0x06] = 0x00
	code[0x07] = 0x00
	code[0x08] = 0x00
	code[0x09] = 0xC3 // ret (establish function boundary)
	code[0x20] = 0x55 // push rbp at target
	code[0x21] = 0x48 // mov rbp, rsp
	code[0x22] = 0x89
	code[0x23] = 0xe5

	candidates, err := resurgo.DetectFunctions(code, 0x1000, resurgo.ArchAMD64)
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range candidates {
		fmt.Printf("0x%x: %s (confidence: %s)\n",
			c.Address, c.DetectionType, c.Confidence)
	}
	// Output:
	// 0x1000: prologue-only (confidence: medium)
	// 0x1020: prologue-callsite (confidence: high)
}
