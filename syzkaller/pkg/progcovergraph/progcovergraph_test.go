package progcovergraph

import (
	"encoding/binary"
	"flag"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"strconv"
	"testing"
	"fmt"

	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/covergraph"
)

var (
	flagChildBlockDict = flag.String("childblockdict", "", "child block listing file")
	flagASMDict        = flag.String("blockasmdict", "", "code block asm listing file")
	flagBlockFuncDict  = flag.String("blockfuncdict", "", "code block function listing file")
	flagTestTraceDir   = flag.String("testtracedir", "", "dir that stores the trace")
	flagShortcutDist   = flag.Int("shortcut", 8, "shortcut distance")
	flagProgFile       = flag.String("progfile", "", "path of the prog file")
)

// Load the raw cover trace of one system call in the prog
func LoadCallCover(traceFilepath string) (*covergraph.CallCover, error) {
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
	return &covergraph.CallCover{Trace: trace}, nil
}

// Load the raw cover trace of all calls in the prog
func LoadProgCover(traceDirpath string) (*covergraph.ProgCover, error) {
	var traceFilenameList []string
	var progCover covergraph.ProgCover

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

// I use this command for test
// go test -blockfuncdict ../covergraph/tmp/analysis/block-func-dict \
// -blockasmdict ../covergraph/tmp/analysis/block-asm-dict \
// -childblockdict ../covergraph/tmp/analysis/block-calling-dict.result \
// -testtracedir ../covergraph/tmp/0007df7cce9cd3599aa876369ff60bb024ef927e/rawcover/run-0/ \
// -shortcut 4 -progfile ../covergraph/tmp/0007df7cce9cd3599aa876369ff60bb024ef927e/prog
func Test(t *testing.T) {
	var logs []*prog.LogEntry

	progTarget, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		panic(fmt.Errorf("cannot init the prog target: %v", err))
	}
	data, err := os.ReadFile(*flagProgFile)
	if err != nil {
		panic("cannot read the prog file")
	}
	logs = progTarget.ParseLog(data)
	if len(logs) == 0 || len(logs) > 1 {
		panic("incorrect number of log entries")
	}
	prog := logs[0].P

	progCover, err := LoadProgCover(*flagTestTraceDir)
	if err != nil {
		panic("cannot read the prog cover trace")
	}

	genConfig := &ProgCoverGraphGeneratorConfig{
		ChildBlockDict:  *flagChildBlockDict,
		BlockASMDict:    *flagASMDict,
		BlockFuncDict:   *flagBlockFuncDict,
		ShortcutEdgeHop: *flagShortcutDist,
	}
	gen := InitProgCoverGraphGenerator(genConfig)

	graphData, err := gen.Generate(prog, progCover)
	if err != nil {
		panic("fail to generate the graph")
	}
	log.Printf("coverNodeCSV: %v", string(graphData.CoverNodeCSV))
	log.Printf("coverEdgeCSV: %v", string(graphData.CoverEdgeCSV))
	log.Printf("progNodeCSV: %v", string(graphData.ProgNodeCSV))
	log.Printf("progEdgeCSV: %v", string(graphData.ProgEdgeCSV))
	log.Printf("connectEdgeCSV: %v", string(graphData.ConnectEdgeCSV))
}
