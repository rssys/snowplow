package covergraph

import (
	"bytes"
	"encoding/csv"
	"encoding/binary"
	"strings"
	"strconv"
	"regexp"

	"github.com/google/syzkaller/pkg/log"
)

type NodeType int

const (
	NodeTypeCovered = iota
	NodeTypeUncovered
)

type NodeID struct {
	Type      NodeType
	BlockAddr uint64
}

type Node struct {
	ID    NodeID
	Index int
}

type EdgeType int

const (
	EdgeTypeCovered EdgeType = iota
	EdgeTypeUncovered
	EdgeTypeCallConnect
	EdgeTypeShortcut
)

type EdgeID struct {
	Type      EdgeType
	SrcNodeID NodeID
	DstNodeID NodeID
}
type Flow = EdgeID

type Edge struct {
	ID      EdgeID
	SrcNode *Node
	DstNode *Node
}

type CoverGraph struct {
	NodeList             []Node
	EdgeList             []Edge
	nodeByNodeID         map[NodeID]*Node
	edgeByEdgeID         map[EdgeID]*Edge
	EntryBlockNodeIDList []NodeID
	LastBlockNodeIDList  []NodeID
}

func (grpah *CoverGraph) SetEntryBlockNodeIDList(entryBlockNodeIDList []NodeID) {
	grpah.EntryBlockNodeIDList = entryBlockNodeIDList
}

func (graph *CoverGraph) SetLastBlockNodeIDList(lastBlockNodeIDList []NodeID) {
	graph.LastBlockNodeIDList = lastBlockNodeIDList
}

func (graph *CoverGraph) GetNode(id NodeID) *Node {
	if node, ok := graph.nodeByNodeID[id]; ok {
		return node
	}
	panic("GetNode() failed. Node not found")
}

func (graph *CoverGraph) addAndGetNode(id NodeID) *Node {
	if node, ok := graph.nodeByNodeID[id]; ok {
		return node
	}
	nodeIdx := len(graph.NodeList)
	node := Node{ID: id, Index: nodeIdx}
	graph.NodeList = append(graph.NodeList, node)
	graph.nodeByNodeID[id] = &node
	return &node
}

func (graph *CoverGraph) addAndGetEdge(id EdgeID) *Edge {
	if edge, ok := graph.edgeByEdgeID[id]; ok {
		return edge
	}
	srcNode := graph.addAndGetNode(id.SrcNodeID)
	dstNode := graph.addAndGetNode(id.DstNodeID)
	edge := Edge{ID: id, SrcNode: srcNode, DstNode: dstNode}
	graph.EdgeList = append(graph.EdgeList, edge)
	graph.edgeByEdgeID[id] = &edge
	return &edge
}

func InitCoverGraph() *CoverGraph {
	return &CoverGraph{
		nodeByNodeID: make(map[NodeID]*Node),
		edgeByEdgeID: make(map[EdgeID]*Edge),
	}
}

func (graph *CoverGraph) AddFlow(flowList []Flow) {
	for _, flow := range flowList {
		graph.addAndGetEdge(flow)
	}
}

// TODO: return errors instead of panic
func (graph *CoverGraph) Export(blockASMDict map[uint64]string, asmTokenDict map[string]int) ([]byte, []byte, []byte) {
	var nodeCSV, edgeCSV bytes.Buffer

	// 1. Save the node information
	nodeRecords := [][]string{
		{"index", "blockaddr", "type"},
	}
	numNode := len(graph.NodeList)
	numASMToken := 48
	nodeFeature := make([][]int, numNode)
	for i := range nodeFeature {
		nodeFeature[i] = make([]int, numASMToken)
	}
	// initialize the feature array with pad tokens
	for i := range nodeFeature {
		for j := range nodeFeature[i] {
			nodeFeature[i][j] = 1 // pad token index
		}
	}

	spaceNormalizer := regexp.MustCompile(`\s+`)
	for nodeIdx, node := range graph.NodeList {
		if nodeIdx != node.Index {
			panic("node list is not sorted")
		}
		// TODO: we should panic if we cannot find the asm
		blockASM, exists := blockASMDict[node.ID.BlockAddr]
		if !exists {
			log.Logf(3, "cannot find asm for block %x\n", node.ID.BlockAddr)
		}
		blockASM = "<s> " + blockASM + " </s>"
		blockASM = spaceNormalizer.ReplaceAllString(blockASM, " ")
		blockASM = strings.TrimSpace(blockASM)
		tokens := strings.Split(blockASM, " ")
		for tokenPos, token := range tokens {
			if tokenPos == numASMToken {
				break
			}
			if tokenIdx, exists := asmTokenDict[token]; exists {
				nodeFeature[nodeIdx][tokenPos] = tokenIdx
			} else {
				nodeFeature[nodeIdx][tokenPos] = 3 // unknown token
			}
		}
		record := []string{
			strconv.Itoa(node.Index),
			strconv.FormatUint(node.ID.BlockAddr, 10),
			strconv.Itoa(int(node.ID.Type)),
		}
		nodeRecords = append(nodeRecords, record)
	}

	var nodeToken bytes.Buffer
	binary.Write(&nodeToken, binary.LittleEndian, int32(numNode))
	binary.Write(&nodeToken, binary.LittleEndian, int32(numASMToken))
	for _, row := range nodeFeature {
		for _, value := range row {
			binary.Write(&nodeToken, binary.LittleEndian, int32(value))
		}
	}

	nodeSave := csv.NewWriter(&nodeCSV)
	if err := nodeSave.WriteAll(nodeRecords); err != nil {
		panic(err)
	}
	nodeSave.Flush()

	// 2. Save the edge information
	edgeRecords := [][]string{
		{"srcindex", "dstindex", "type"},
	}
	for _, edge := range graph.EdgeList {
		record := []string{
			strconv.Itoa(edge.SrcNode.Index),
			strconv.Itoa(edge.DstNode.Index),
			strconv.Itoa(int(edge.ID.Type)),
		}
		edgeRecords = append(edgeRecords, record)
	}
	edgeSave := csv.NewWriter(&edgeCSV)
	if err := edgeSave.WriteAll(edgeRecords); err != nil {
		panic(err)
	}
	edgeSave.Flush()

	return nodeCSV.Bytes(), nodeToken.Bytes(), edgeCSV.Bytes()
}

func (graph *CoverGraph) IsEmpty() bool {
	return len(graph.NodeList) == 0 && len(graph.EdgeList) == 0
}
