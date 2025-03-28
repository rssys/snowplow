package covergraph

import (
	"os"
	"strconv"
	"strings"
)

type KernelCFG struct {
	// return the set of child blocks given the parent block addr
	ChildBlockByBlock map[uint64]map[uint64]bool
	ASMByBlock        map[uint64]string
	funcByBlock       map[uint64]string
	ASMTokenDict      map[string]int
}

// Build dictionary that takes the starting address of one code block
// and returns the string of its function name
// The input file should follow a specific format:
// BLOCK_ADDR FUNC_NAME
// For example:
// 0xffffffff81000300 sev_verify_cbit
func (cfg *KernelCFG) LoadBlockFunc(blockFuncFilepath string) {
	content, err := os.ReadFile(blockFuncFilepath)
	if err != nil {
		panic(err)
	}

	blockFuncMap := make(map[uint64]string)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		address, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			continue
		}
		blockFuncMap[address] = parts[1]
	}
	cfg.funcByBlock = blockFuncMap
}

// Build dictionary that takes the starting address of one code block
// and returns the string of its assembly code
// The input file should follow a specific format:
// BLOCK_ADDR ASM_STRING(lines are concatenated with ";")
// For example:
// 0xffffffff81000300 endbr64 ; mov %rdi,%rax ; jmpq ffffffff8222d310 <__x86_return_thunk> ;
func (cfg *KernelCFG) LoadBlockASM(blockASMFilepath string) {
	content, err := os.ReadFile(blockASMFilepath)
	if err != nil {
		panic(err)
	}

	blockASMMap := make(map[uint64]string)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		address, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			continue
		}
		blockASMMap[address] = parts[1]
	}
	cfg.ASMByBlock = blockASMMap
}

// Build a dictionary that takes the starting address of one code block
// and returns the set of child blocks if any
// The input file should follow a specific format:
// PARENT_BLOCK_ADDR CHILD_BLOCK_ADDR_1 CHILD_BLOCK_ADDR_2 ...
// For example:
// 0xffffffff8100f720 0xffffffff8100f745 0xffffffff8100f73b
func (cfg *KernelCFG) LoadChildBlockDict(childBlockDictFilepath string) {
	childBlockDict := make(map[uint64]map[uint64]bool)

	content, err := os.ReadFile(childBlockDictFilepath)
	if err != nil {
		panic(err)
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Split line into parts
		parts := strings.Fields(line)

		// Convert the first part to uint64 and use it as the parentBlockAddr
		parentBlockAddr, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			panic(err)
		}

		// Check if the key exists in the map; if not, initialize the inner map
		if _, exists := childBlockDict[parentBlockAddr]; !exists {
			childBlockDict[parentBlockAddr] = make(map[uint64]bool)
		}

		// Iterate over the remaining parts, convert them to uint64, and add them to the set
		for _, part := range parts[1:] {
			childBlockAddr, err := strconv.ParseUint(part, 0, 64)
			if err != nil {
				panic(err)
			}
			childBlockDict[parentBlockAddr][childBlockAddr] = true
		}
	}
	cfg.ChildBlockByBlock = childBlockDict
}

func (cfg *KernelCFG) LoadASMTokenDict(asmTokenDictFilepath string) {
	tokenDict := make(map[string]int)
	content, err := os.ReadFile(asmTokenDictFilepath)
	if err != nil {
		panic(err)
	}
	tokenDict["<s>"] = 0
	tokenDict["</s>"] = 2
	tokenDict["<unk>"] = 3
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			panic("wrong dict format")
		}
		token := parts[0]
		index := i + 4 // offset by 4 as we have 4 special tokens before asm tokens
		tokenDict[token] = index
	}
	cfg.ASMTokenDict = tokenDict
}
