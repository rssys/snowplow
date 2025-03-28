package proggraph

import (
	"bytes"
	"encoding/csv"
	"math/rand"
	"fmt"
	"log"
	"strconv"
	"testing"

	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/prog"
)

type progGraph struct {
	callNodeIdxList []int
	numArgByCall    []int
}

func LoadProgGraph(progNodeCSV []byte) *progGraph {
	var nodeIdxList []int
	var numArgList []int
	var firstNodeIdx int

	// Create a new reader for the byte slice
	reader := csv.NewReader(bytes.NewReader(progNodeCSV))
	// Read all the records from the csv
	records, err := reader.ReadAll()
	if err != nil {
		return nil
	}

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
		}
	}
	for callIdx := range nodeIdxList {
		numArg := -1
		if callIdx == len(nodeIdxList) - 1 {
			numArg = (len(records) - 2) - nodeIdxList[callIdx]
		} else {
			numArg = nodeIdxList[callIdx+1] - nodeIdxList[callIdx] - 1 // call-node3, callnode-0 two args
		}
		numArgList = append(numArgList, numArg)
	}
	return &progGraph{callNodeIdxList: nodeIdxList, numArgByCall: numArgList}
}


func TestProgGraph(t *testing.T) {
	progTarget, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		panic(fmt.Errorf("cannot init the prog target: %v", err))
	}

	choiceTable := progTarget.BuildChoiceTable(nil, nil)
	for i := 0; i < 1000; i++ {
		p := progTarget.Generate(rand.NewSource(int64(626+i)), 30, choiceTable)
		graph := GenerateGraph(p)
		nodeCSV, _ := graph.Export()
		progGraph := LoadProgGraph(nodeCSV)
		//log.Printf("nodeCSV: %v", string(nodeCSV))
		//log.Printf("edgeCSV: %v", string(edgeCSV))
		log.Printf("%v", string(p.Serialize()))
		for callIdx := range p.Calls {
			numArg := prog.CountCallArg(p, callIdx)
			if numArg != progGraph.numArgByCall[callIdx] {
				panic("inconsistent arg num")
			}
			//log.Printf("prog-%v call-%v numArg=%v numArgNode=%v", i, callIdx, numArg, progGraph.numArgByCall[callIdx])
		}
	}
}
