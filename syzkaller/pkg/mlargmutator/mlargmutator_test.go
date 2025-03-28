package mlargmutator

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aclements/go-moremath/stats"
	"github.com/google/syzkaller/pkg/covergraph"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagKernelAnalysisDir = flag.String("kernelanalysis", "", "dir stores the kernel analysis data")
	flagTestDatasetDir    = flag.String("testdataset", "", "dir stores the mutation profile data")
	flagNumWorker         = flag.Int("numworker", 0, "num of worker to do inference in paralle")
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

func (builder *DatasetBuilder) loadProg(progFile string) *prog.Prog {
	data, err := os.ReadFile(progFile)
	if err != nil {
		return nil
	}
	logs := builder.target.ParseLog(data)
	if len(logs) == 0 {
		return nil
	}
	return logs[0].P
}

func (builder *DatasetBuilder) loadRequestFromThisProg(progDataDir string) {
	// load the prog
	progFile := path.Join(progDataDir, "prog")
	p := builder.loadProg(progFile)
	if p == nil {
		//log.Printf("cannot load prog %v", progFile)
		return
	}

	coverDataDirpath := path.Join(progDataDir, "rawcover", "run-0")
	if _, err := os.Stat(coverDataDirpath); err != nil {
		log.Fatalf("raw coverage data does not exist %v", coverDataDirpath)
	}
	progCover, err := LoadProgCover(coverDataDirpath)
	if err != nil {
		//log.Printf("cannot read the prog cover trace")
		return
	}
	coverSize := 0
	for _, callCover := range progCover.CallList {
		coverSize += len(callCover.Trace)
	}
	if coverSize == 0 {
		//log.Printf("empty cover found %v", coverDataDirpath)
		return
	}
	if len(progCover.CallList) != len(p.Calls) {
		return
	}

	builder.reqList <- &Request{P: p, ProgCover: progCover}
}

type DatasetBuilder struct {
	target  *prog.Target
	reqList chan *Request
}

func (builder *DatasetBuilder) buildTestDataset(datasetDir string) {
	entryList, err := os.ReadDir(datasetDir)
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	for _, entry := range entryList {
		if entry.IsDir() != true {
			continue
		}
		progDataDir := path.Join(datasetDir, entry.Name())
		wg.Add(1)
		go func() {
			builder.loadRequestFromThisProg(progDataDir)
			wg.Done()
		}()
	}
	wg.Wait()
}

type WorkerPool struct {
	mutator     *MLArgMutator
	requestChan chan *Request
	latencyChan chan *time.Duration
	waitGroup   sync.WaitGroup
}

func (pool *WorkerPool) handleMLRequest(mutator *MLArgMutator) {
	for {
		req := <- pool.requestChan
		if req == nil {
			//log.Printf("no tests anymore, exits")
			break
		}
		start := time.Now()
		mutator.PredictProg(req)
		predictLatency := time.Since(start)
		pool.latencyChan <- &predictLatency
	}
	pool.waitGroup.Done()
}

func Test(t *testing.T) {

	config := &MLArgMutatorConfig{
		ChildBlockDict:  path.Join(*flagKernelAnalysisDir, "block-calling-dict.result"),
		BlockASMDict:    path.Join(*flagKernelAnalysisDir, "block-asm-dict"),
		BlockFuncDict:   path.Join(*flagKernelAnalysisDir, "block-func-dict"),
		ASMTokenDict:    path.Join(*flagKernelAnalysisDir, "asm-token-dict"),
		ShortcutEdgeHop: 8,
		ServerAddr:      "localhost:7070",
		ServerKey:       "",
	}

	progTarget, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		panic("cannot init the prog target: %v")
	}
	builder := &DatasetBuilder{target: progTarget}
	builder.reqList = make(chan *Request, 2000000)
	builder.buildTestDataset(*flagTestDatasetDir)
	numRequest := len(builder.reqList)
	log.Printf("found %v requests as the test", numRequest)
	close(builder.reqList)

	mutator := InitMLArgMutator(config)
	pool := WorkerPool{
		mutator: mutator,
		requestChan: builder.reqList,
		latencyChan: make(chan *time.Duration, 2000000),
	}

	start := time.Now()
	for i := 0; i < *flagNumWorker; i++ {
		pool.waitGroup.Add(1)
		go pool.handleMLRequest(mutator)
	}
	pool.waitGroup.Wait()
	totalTime := time.Since(start)

	throughput := float64(numRequest / int(totalTime.Seconds()))
	fmt.Printf("throughput %.4f\n", throughput)

	latencyList := make([]float64, 0)
	for {
		duration := <-pool.latencyChan
		if duration == nil {
			break
		}
		latencyList = append(latencyList, float64(duration.Milliseconds()))
		if len(latencyList) == numRequest {
			break
		}
	}
	mean, lo, hi := stats.MeanCI(latencyList, 0.95)
	fmt.Printf("mean %.4f\n", mean)
	fmt.Printf("lo %.4f\n", lo)
	fmt.Printf("hi %.4f\n", hi)
}
