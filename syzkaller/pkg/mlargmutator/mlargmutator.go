package mlargmutator

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/covergraph"
	"github.com/google/syzkaller/pkg/inference"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/progcovergraph"
	"github.com/google/syzkaller/prog"
)

type MLArgMutator struct {
	Generator       *progcovergraph.ProgCoverGraphGenerator
	Config          *MLArgMutatorConfig
	NumPredict      atomic.Int64
	Client          *inference.Connector
}

type MLArgMutatorConfig struct {
	ChildBlockDict  string
	BlockASMDict    string
	BlockFuncDict   string
	ASMTokenDict    string
	ShortcutEdgeHop int
	ServerAddr      string
	ServerKey       string
}

func InitMLArgMutator(config *MLArgMutatorConfig) *MLArgMutator {
	genConfig := &progcovergraph.ProgCoverGraphGeneratorConfig{
		ChildBlockDict:  config.ChildBlockDict,
		BlockASMDict:    config.BlockASMDict,
		BlockFuncDict:   config.BlockFuncDict,
		ASMTokenDict:    config.ASMTokenDict,
	}
	generator := progcovergraph.InitProgCoverGraphGenerator(genConfig)
	connector := inference.InitConnect(config.ServerAddr, config.ServerKey)
	return &MLArgMutator{
		Generator:       generator,
		Config:          config,
		NumPredict:      atomic.Int64{},
		Client:          connector,
	}
}

type Request struct {
	P         *prog.Prog
	ProgCover *covergraph.ProgCover
}

func (mutator *MLArgMutator) PredictProg(req *Request) map[prog.ArgLocator]bool {
	suggestions := make(map[prog.ArgLocator]bool, 0)

	graphData, err := mutator.Generator.Generate(req.P, req.ProgCover)
	if err != nil {
		log.Fatalf("cannot generate the graph: %v", err)
		return nil
	}

	mutator.NumPredict.Add(1)
	log.Logf(2, "currently have %v programs in the queue", mutator.NumPredict.Load())

	progGraph := mutator.LoadProgGraph(graphData.ProgNodeCSV)

	input := make(map[string][]byte)
	input["cover.node"] = graphData.CoverNodeCSV
	input["cover.node.token"] = graphData.CoverNodeToken
	input["cover.edge"] = graphData.CoverEdgeCSV
	input["prog.node"] = graphData.ProgNodeCSV
	input["prog.edge"] = graphData.ProgEdgeCSV
	input["fuseedge.edge"] = graphData.ConnectEdgeCSV

	start := time.Now()
	posNodeIdxList, err := mutator.Client.Predict(input)
	predictLatency := time.Since(start)

	if err != nil {
		log.Fatalf("%v", err)
	}
	for _, posNodeIdx := range posNodeIdxList {
		argLoc, err := progGraph.LocateArg(posNodeIdx)
		if err != nil {
			continue
		}
		if prog.IsArgMutatable(req.P, argLoc) == true {
			suggestions[argLoc] = true
		}
	}
	log.Logf(1, "num(selected-args)=%v latency=%d", len(suggestions), predictLatency.Milliseconds())
	mutator.NumPredict.Add(-1)
	return suggestions
}

// TODO: re-implement once we have the reachibility predictor
func (mutator *MLArgMutator) PredictPromisingURB(graphData *progcovergraph.ProgCoverGraphData) []int {
	var indexList []int

	// Create a new reader for the byte slice
	reader := csv.NewReader(bytes.NewReader(graphData.CoverNodeCSV))
	// Read all the records from the csv
	records, err := reader.ReadAll()
	if err != nil {
		return nil
	}

	// Iterate over the records and find rows with "type" value 1
	for i, record := range records {
		// Skip the header row
		if i == 0 {
			continue
		}
		// Parse the "type" value
		typeVal, err := strconv.Atoi(record[2])
		if err != nil {
			return nil
		}
		// Check if the "type" value is 1
		if typeVal == 1 {
			// Parse the "index" value
			indexVal, err := strconv.Atoi(record[0])
			if err != nil {
				return nil
			}
			indexList = append(indexList, indexVal)
		}
	}
	return indexList
}

type coverGraph struct {
	BlockAddrByNodeIdx map[int]uint64
}

func (mutator *MLArgMutator) LoadCoverGraph(coverNodeCSV []byte) *coverGraph{
	coverGraph := &coverGraph{}
	coverGraph.BlockAddrByNodeIdx = make(map[int]uint64)

	reader := csv.NewReader(bytes.NewReader(coverNodeCSV))
	// Read all the records from the csv
	records, err := reader.ReadAll()
	if err != nil {
		return nil
	}

	for i, record := range records {
		// Skip the header row
		if i == 0 {
			continue
		}
		nodeIdx, err := strconv.Atoi(record[0])
		if err != nil {
			return nil
		}
		blockAddr, err := strconv.ParseUint(record[1], 10, 64)
		if err != nil {
			return nil
		}
		coverGraph.BlockAddrByNodeIdx[nodeIdx] = blockAddr
	}
	return coverGraph
}

type progGraph struct {
	callNodeIdxList []int
	argNodeIdxMap   map[int]bool
}

func (mutator *MLArgMutator) LoadProgGraph(progNodeCSV []byte) *progGraph {
	var nodeIdxList []int
	var firstNodeIdx int

	// Create a new reader for the byte slice
	reader := csv.NewReader(bytes.NewReader(progNodeCSV))
	// Read all the records from the csv
	records, err := reader.ReadAll()
	if err != nil {
		return nil
	}

	argNodeIdxMap := make(map[int]bool, 0)
	firstNodeIdx = -1
	for i, record := range records {
		// Skip the header row
		if i == 0 {
			continue
		}
		// Parse the "type" value
		typeVal, err := strconv.Atoi(record[2])
		if err != nil {
			return nil
		}
		// check for call node
		if typeVal == 0 {
			// Parse the "index" value
			indexVal, err := strconv.Atoi(record[0])
			if err != nil {
				return nil
			}
			if firstNodeIdx < 0 {
				firstNodeIdx = indexVal
			}
			nodeIdxList = append(nodeIdxList, indexVal - firstNodeIdx)
		} else if typeVal == 1 {
			indexVal, err := strconv.Atoi(record[0])
			if err != nil {
				return nil
			}
			argNodeIdxMap[indexVal - firstNodeIdx] = true
		}
	}
	return &progGraph{callNodeIdxList: nodeIdxList, argNodeIdxMap: argNodeIdxMap}
}

func (graph *progGraph) LocateArg(nodeIdx int) (prog.ArgLocator, error) {
	if exists := graph.argNodeIdxMap[nodeIdx]; !exists {
		return prog.ArgLocator{CallIdx: -1, ArgIdx: -1}, fmt.Errorf("non-arg proggraph node")
	}
	callIdx := 0
	// find out which call does the arg belong to
	for ;; {
		if callIdx == len(graph.callNodeIdxList) - 1 {
			break
		}
		if graph.callNodeIdxList[callIdx+1] > nodeIdx {
			break
		}
		callIdx += 1
	}
	return prog.ArgLocator{
		CallIdx: callIdx,
		ArgIdx: nodeIdx - graph.callNodeIdxList[callIdx] - 1,
	}, nil
}
