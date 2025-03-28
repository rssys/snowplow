package covergraph

import (
	"encoding/binary"
	"flag"
	"testing"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

var (
	flagChildBlockDict = flag.String("childblockdict", "", "child block listing file")
	flagASMDict        = flag.String("blockasmdict", "", "code block asm listing file")
	flagBlockFuncDict  = flag.String("blockfuncdict", "", "code block function listing file")
	flagTestTraceDir   = flag.String("testtracedir", "", "dir that stores the trace")
	flagASMTokenDict   = flag.String("asmtokendict", "", "asm token dict")
	flagShortcutDist   = flag.Int("shortcut", 8, "shortcut distance")
)

// Load the raw cover trace of one system call in the prog
func LoadCallCover(traceFilepath string) (*CallCover, error) {
	file, err := os.Open(traceFilepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	data := make([]byte, fileInfo.Size())
	_, err = file.Read(data)
	if err != nil {
		return nil, err
	}

	numElements := len(data) / 4
	trace := make([]uint64, numElements)

	for i := 0; i < numElements; i++ {
		val := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		trace[i] = (0xffffffff << 32) + uint64(val)
	}
	return &CallCover{Trace: trace}, nil
}

// Load the raw cover trace of all calls in the prog
func LoadProgCover(traceDirpath string) (*ProgCover, error) {
	var traceFilenameList []string
	var progCover ProgCover

	dirList, err := os.ReadDir(traceDirpath)
	if err != nil {
		panic("cannot read the raw cover folder")
	}

	for _, file := range dirList {
		if strings.HasPrefix(file.Name(), "call.") {
			traceFilenameList = append(traceFilenameList, file.Name())
		}
	}

	sort.Slice(traceFilenameList, func(i, j int) bool {
		idxI, _ := strconv.Atoi(strings.TrimPrefix(traceFilenameList[i], "call."))
		idxJ, _ := strconv.Atoi(strings.TrimPrefix(traceFilenameList[j], "call."))
		return idxI < idxJ
	})

	for _, traceFilename := range traceFilenameList {
		traceFilepath := path.Join(traceDirpath, traceFilename)
		callCover, err := LoadCallCover(traceFilepath)
		if err != nil {
			return nil, err
		}
		progCover.CallList = append(progCover.CallList, *callCover)
	}
	return &progCover, nil
}

func report(graph *CoverGraph) {
	numNode := len(graph.NodeList)
	numEdge := len(graph.EdgeList)
	log.Printf("the graph contains %v nodes and %v edges\n", numNode, numEdge)
}

// I use this command for test
// go test -blockfuncdict tmp/analysis/block-func-dict \
// -blockasmdict tmp/analysis/block-asm-dict \
// -childblockdict tmp/analysis/block-calling-dict.result \
// -testtracedir tmp/0007df7cce9cd3599aa876369ff60bb024ef927e/rawcover/run-0/ \
// -shortcut 4
func TestCoverGraph(t *testing.T) {
	var kernelCFG *KernelCFG

	kernelCFG = &KernelCFG{}
	kernelCFG.LoadChildBlockDict(*flagChildBlockDict)
	kernelCFG.LoadBlockASM(*flagASMDict)
	kernelCFG.LoadBlockFunc(*flagBlockFuncDict)
	kernelCFG.LoadASMTokenDict(*flagASMTokenDict)

	log.Printf("kernel CFG is loaded")

	progCover, err := LoadProgCover(*flagTestTraceDir)
	if err != nil {
		panic("cannot read the prog cover trace")
	}

	graph := InitCoverGraph()
	flowAnalysisResult := kernelCFG.ExtractFlow(progCover, *flagShortcutDist)
	coveredFlowList := flowAnalysisResult.CoveredFlowList
	uncoveredFlowList := flowAnalysisResult.UncoveredFlowList
	shortcutFlowList := flowAnalysisResult.ShortcutFlowList
	entryBlockNodeIDList := flowAnalysisResult.EntryBlockNodeIDList
	lastBlockNodeIDList := flowAnalysisResult.LastBlockNodeIDList

	graph.SetEntryBlockNodeIDList(entryBlockNodeIDList)
	graph.SetLastBlockNodeIDList(lastBlockNodeIDList)
	graph.AddFlow(coveredFlowList)
	report(graph)
	graph.AddFlow(uncoveredFlowList)
	report(graph)
	graph.AddFlow(shortcutFlowList)
	report(graph)

	nodeCSV, _, edgeCSV := graph.Export(kernelCFG.ASMByBlock, kernelCFG.ASMTokenDict)
	log.Printf("nodeCSV: %v", string(nodeCSV))
	log.Printf("edgeCSV: %v", string(edgeCSV))
}
