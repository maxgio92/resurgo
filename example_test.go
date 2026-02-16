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
