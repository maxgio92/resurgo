package resurgo_test

import (
	"debug/elf"
	"fmt"
	"log"

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

func ExampleDetectFunctionsFromELF() {
	f, err := elf.Open("/usr/bin/ls")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	candidates, err := resurgo.DetectFunctionsFromELF(f)
	if err != nil {
		log.Fatal(err)
	}

	// Count candidates by detection type.
	counts := make(map[resurgo.DetectionType]int)
	for _, c := range candidates {
		counts[c.DetectionType]++
	}
	fmt.Printf("total: %d\n", len(candidates))
	fmt.Printf("prologue+callsite: %d\n", counts[resurgo.DetectionPrologueCallSite])
	fmt.Printf("cfi: %d\n", counts[resurgo.DetectionCFI])
}
