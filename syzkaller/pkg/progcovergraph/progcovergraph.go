package progcovergraph

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"

	"github.com/google/syzkaller/pkg/covergraph"
	"github.com/google/syzkaller/pkg/proggraph"
)

type CallToCoverEdge struct {
	srcNode *proggraph.Node
	dstNode *covergraph.Node
}

type CallToProgEdge struct {
	srcNode *covergraph.Node
	dstNode *proggraph.Node
}

type ProgCoverGraph struct {
	coverGraph           *covergraph.CoverGraph
	progGraph            *proggraph.ProgGraph
	connectCoverEdgeList []CallToCoverEdge
	connectProgEdgeList  []CallToProgEdge
}

// Generate the program coverage graph
func GenerateGraph(progGraph *proggraph.ProgGraph, coverGraph *covergraph.CoverGraph) *ProgCoverGraph {
	// update the node index for the program graph by offsetting the index by the number of nodes in the coverage graph
	updateNodeIndex(progGraph.NodeList, len(coverGraph.NodeList))
	connectCoverEdgeList, connectProgEdgeList := getConnectEdgeList(progGraph, coverGraph)
	return &ProgCoverGraph{
		coverGraph:           coverGraph,
		progGraph:            progGraph,
		connectCoverEdgeList: connectCoverEdgeList,
		connectProgEdgeList:  connectProgEdgeList,
	}
}

// Generate the connect edges between the program graph and the coverage graph
// (1) connect cover edge is from the syscall node in the program graph to the entry block node in the coverage graph
// (2) connect prog edge is from the last block node in the coverage graph to the syscall node in the program graph
func getConnectEdgeList(progGraph *proggraph.ProgGraph, coverGraph *covergraph.CoverGraph) ([]CallToCoverEdge, []CallToProgEdge) {
	// get the entry block addresses for syscalls in the program trace
	EntryBlockNodeIDList := coverGraph.EntryBlockNodeIDList
	LastBlockNodeIDList := coverGraph.LastBlockNodeIDList
	if len(EntryBlockNodeIDList) != len(progGraph.CallNodePosList) || len(EntryBlockNodeIDList) != len(LastBlockNodeIDList) {
		panic("Connect node count mismatch. Connect program and coverage failed!")
	}

	connectCoverEdgeList := []CallToCoverEdge{}
	connectProgEdgeList := []CallToProgEdge{}

	for idx, callNodePos := range progGraph.CallNodePosList {
		// 1. add connectCoverEdge
		// find the syscall node in the program graph
		srcSyscallNode := progGraph.NodeList[callNodePos]
		// find the corresponding entry block node with the node ID
		entryCoverNodeID := EntryBlockNodeIDList[idx]
		dstEntryCoverNode := coverGraph.GetNode(entryCoverNodeID)

		connectCoverEdge := CallToCoverEdge{srcNode: srcSyscallNode, dstNode: dstEntryCoverNode}
		connectCoverEdgeList = append(connectCoverEdgeList, connectCoverEdge)

		// 2. add connectProgEdge
		// find the last block node in the coverage graph
		lastCoverNodeID := LastBlockNodeIDList[idx]
		srcLastCoverNode := coverGraph.GetNode(lastCoverNodeID)
		// the destination node is the syscall node in the program graph
		dstSyscallNode := srcSyscallNode

		connectProgEdge := CallToProgEdge{srcNode: srcLastCoverNode, dstNode: dstSyscallNode}
		connectProgEdgeList = append(connectProgEdgeList, connectProgEdge)
	}

	return connectCoverEdgeList, connectProgEdgeList
}

func (graph *ProgCoverGraph) PrintConnectEdges() {
	for _, edge := range graph.connectCoverEdgeList {
		fmt.Printf("Connect edge: %s -> %s\n", edge.srcNode.Name, strconv.FormatUint(edge.dstNode.ID.BlockAddr, 16))
	}
	for _, edge := range graph.connectProgEdgeList {
		fmt.Printf("Connect edge: %s -> %s\n", strconv.FormatUint(edge.srcNode.ID.BlockAddr, 16), edge.dstNode.Name)
	}
}

// Update the node index for the program graph by adding the offset
func updateNodeIndex(nodeList []*proggraph.Node, offset int) {
	for idx, node := range nodeList {
		node.Index = idx + offset
	}
}

// Export the connect edges to a csv file
func (graph *ProgCoverGraph) exportConnectEdges() []byte {
	var edgeCSV bytes.Buffer

	connectEdgeRecords := [][]string{
		{"srcindex", "dstindex"},
	}
	// export connectCoverEdges
	for _, edge := range graph.connectCoverEdgeList {
		record := []string{
			strconv.Itoa(edge.srcNode.Index),
			strconv.Itoa(edge.dstNode.Index),
		}
		connectEdgeRecords = append(connectEdgeRecords, record)
	}
	// export connectProgEdges
	for _, edge := range graph.connectProgEdgeList {
		record := []string{
			strconv.Itoa(edge.srcNode.Index),
			strconv.Itoa(edge.dstNode.Index),
		}
		connectEdgeRecords = append(connectEdgeRecords, record)
	}
	edgeSave := csv.NewWriter(&edgeCSV)
	if err := edgeSave.WriteAll(connectEdgeRecords); err != nil {
		panic(err)
	}
	edgeSave.Flush()

	return edgeCSV.Bytes()
}

type ProgCoverGraphData struct {
	CoverNodeCSV   []byte
	CoverNodeToken []byte
	CoverEdgeCSV   []byte
	ProgNodeCSV    []byte
	ProgEdgeCSV    []byte
	ConnectEdgeCSV []byte
}

// Export the graph information to csv files
// There will be five files: node info and edge info for coverage graph, node info and edge info for program graph, and connect edge info
func (graph *ProgCoverGraph) Export(blockASMDict map[uint64]string, asmTokenDict map[string]int) *ProgCoverGraphData {
	// 1. Export the coverage graph
	coverNodeCSV, coverNodeToken, coverEdgeCSV := graph.coverGraph.Export(blockASMDict, asmTokenDict)

	// 2. Export the program graph
	progNodeCSV, progEdgeCSV := graph.progGraph.Export()

	// 3. Export the connect edge info
	connectEdgeCSV := graph.exportConnectEdges()

	return &ProgCoverGraphData{
		CoverNodeCSV:   coverNodeCSV,
		CoverNodeToken: coverNodeToken,
		CoverEdgeCSV:   coverEdgeCSV,
		ProgNodeCSV:    progNodeCSV,
		ProgEdgeCSV:    progEdgeCSV,
		ConnectEdgeCSV: connectEdgeCSV,
	}
}
