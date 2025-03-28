package proggraph

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/google/syzkaller/prog"
)

type NodeType int

const (
	NodeTypeCall NodeType = iota
	NodeTypeArg
)

type EdgeType int

const (
	EdgeTypeControl EdgeType = iota
	EdgeTypeArg
	EdgeTypeSiblingArg
)

type Node struct {
	Type   NodeType
	Name   string
	Index  int
}

type Edge struct {
	Type    EdgeType
	SrcNode *Node
	DstNode *Node
}

type ProgGraph struct {
	NodeList []*Node
	EdgeList []*Edge
	// remember what is the corresponding
	// arg for each argument node
	ArgNodeMap map[uintptr]*Node
	// the position of syscall nodes in the NodeList[]
	// TODO: introduce the NodeID for the program graph
	// so that we can directly find the corresponding node
	CallNodePosList []int
}

// TODO: re-implement this functionality so that we use the argument idx
// to locate the corresponding argnode
func (graph *ProgGraph) FindArgNode(arg *prog.Arg) *Node {
	argNode, exists := graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))]
	if !exists {
		panic("cannot find the argnode")
	}
	return argNode
}

func (graph *ProgGraph) addNode(node *Node) {
	node.Index = len(graph.NodeList)
	graph.NodeList = append(graph.NodeList, node)
}

func (graph *ProgGraph) addEdge(edge *Edge) {
	graph.EdgeList = append(graph.EdgeList, edge)
}

type generator struct {
	graph      *ProgGraph
	resNodeMap map[*prog.ResultArg]*Node
}

type ArgCtx struct {
	Parent  *Node
	Sibling *Node
}

// Create a new resource node and map the Arg pointer to this node,
// so that we can find this node later when this resource is used.
func (g *generator) getResNode(res *prog.ResultArg) *Node {
	if resNode, exists := g.resNodeMap[res]; exists {
		return resNode
	}
	resNode := &Node{
		Type: NodeTypeArg,
		Name: fmt.Sprintf("resource (%v)", res.Label()),
	}
	g.resNodeMap[res] = resNode
	return resNode
}

func (g *generator) addArgNode(argNode *Node, ctx *ArgCtx) {
	g.graph.addNode(argNode)
	argEdge := &Edge{
		Type:    EdgeTypeArg,
		DstNode: ctx.Parent,
		SrcNode: argNode,
	}
	g.graph.addEdge(argEdge)
	if ctx.Sibling == nil {
		return
	}
	argEdge = &Edge{
		Type:    EdgeTypeSiblingArg,
		SrcNode: ctx.Sibling,
		DstNode: argNode,
	}
	g.graph.addEdge(argEdge)

}

func (g *generator) analyzeArg(arg *prog.Arg, ctx *ArgCtx) *Node {
	// backup the ctx because we may need a different ctx
	// in the recursive case
	ctxBackup := *ctx
	defer func() { *ctx = ctxBackup }()

	switch a := (*arg).(type) {
	case *prog.ConstArg:
		argNode := &Node{
			Type:   NodeTypeArg,
			Name:   fmt.Sprintf("constant (%v)", a.Label()),
		}
		g.addArgNode(argNode, ctx)
		g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
		return argNode

	case *prog.PointerArg:
		argNode := &Node{
			Type:   NodeTypeArg,
			Name:   fmt.Sprintf("pointer (%v)", a.Label()),
		}
		g.addArgNode(argNode, ctx)
		g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
		if a.Res != nil {
			ctx.Parent = argNode
			ctx.Sibling = nil
			g.analyzeArg(&a.Res, ctx)
		}
		return argNode

	case *prog.DataArg:
		argNode := &Node{
			Type:   NodeTypeArg,
			Name:   fmt.Sprintf("data (%v)", a.Label()),
		}
		g.addArgNode(argNode, ctx)
		g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
		return argNode

	case *prog.GroupArg:
		argNode := &Node{
			Type:   NodeTypeArg,
			Name:   fmt.Sprintf("group (%v)", a.Label()),
		}
		g.addArgNode(argNode, ctx)
		g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
		// go over each inner
		ctx.Parent = argNode
		ctx.Sibling = nil
		for innerIdx := range a.Inner {
			subArgNode := g.analyzeArg(&a.Inner[innerIdx], ctx)
			ctx.Sibling = subArgNode
		}
		return argNode

	case *prog.UnionArg:
		argNode := &Node{
			Type:   NodeTypeArg,
			Name:   fmt.Sprintf("union (%v)", a.Label()),
		}
		g.addArgNode(argNode, ctx)
		g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
		if a.Option != nil {
			ctx.Parent = argNode
			ctx.Sibling = nil
			g.analyzeArg(&a.Option, ctx)
		}
		return argNode

	case *prog.ResultArg:
		var argNode *Node
		if a.InUse() {
			if _, exists := g.resNodeMap[a]; exists {
				panic("resNode already exists")
			}
			resNode := g.getResNode(a)
			argNode = resNode
			g.addArgNode(resNode, ctx)
			g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = resNode
			ctx.Parent = resNode
			ctx.Sibling = nil
		} else {
			argNode = &Node{
				Type:   NodeTypeArg,
				Name:   fmt.Sprintf("resource (%v)", a.Label()),
			}
			g.addArgNode(argNode, ctx)
			g.graph.ArgNodeMap[uintptr(unsafe.Pointer(arg))] = argNode
			ctx.Parent = argNode
			ctx.Sibling = nil
		}
		// add a alias edge if this resource is a reference to another argNode
		if a.Res != nil {
			aliasResNode := g.getResNode(a.Res)
			resEdge := &Edge{
				Type:    EdgeTypeArg,
				SrcNode: aliasResNode,
				DstNode: ctx.Parent,
			}
			g.graph.addEdge(resEdge)
		}
		return argNode
	default:
		panic("arg type is not supported")
	}
}

// Create the program graph given the program
func GenerateGraph(p *prog.Prog) *ProgGraph {
	var lastCallNode *Node

	graph := &ProgGraph{
		ArgNodeMap: make(map[uintptr]*Node),
	}
	g := &generator{
		resNodeMap: make(map[*prog.ResultArg]*Node),
		graph:      graph,
	}

	for callIdx := range p.Calls {
		// 1. create the system call node
		callNode := &Node{
			Type:   NodeTypeCall,
			Name:   p.Calls[callIdx].Meta.Name,
		}
		g.graph.addNode(callNode)
		// add the call index to the list
		// which will be used when connecting the program and coverage graph
		g.graph.CallNodePosList = append(g.graph.CallNodePosList, callNode.Index)

		// 2. connect this call with the prior call (if any)
		if lastCallNode != nil {
			callEdge := &Edge{
				Type:    EdgeTypeControl,
				SrcNode: lastCallNode,
				DstNode: callNode,
			}
			g.graph.addEdge(callEdge)
		}

		// 3. create the resource node for the return value (if any)
		if p.Calls[callIdx].Ret != nil {
			resNode := g.getResNode(p.Calls[callIdx].Ret)
			g.graph.addNode(resNode)
			// the call should point to the resource node, to indicate
			// that the resource node is the outcome of the call.
			resEdge := &Edge{
				Type:    EdgeTypeArg,
				SrcNode: callNode,
				DstNode: resNode,
			}
			g.graph.addEdge(resEdge)
		}

		// 4. create the argument node
		ctx := &ArgCtx{
			Parent:  callNode,
			Sibling: nil,
		}
		for argIdx := range p.Calls[callIdx].Args {
			argNode := g.analyzeArg(&(p.Calls[callIdx].Args[argIdx]), ctx)
			// maintain the sibling node for positional edges
			ctx.Sibling = argNode
		}
		lastCallNode = callNode
	}
	return g.graph
}

func (graph *ProgGraph) Export() ([]byte, []byte) {
	var nodeCSV, edgeCSV bytes.Buffer

	// 1. Save the node information
	nodeRecords := [][]string{
		{"index", "name", "type"},
	}
	for _, node := range graph.NodeList {
		record := []string{
			strconv.Itoa(node.Index),
			node.Name,
			strconv.Itoa(int(node.Type)),
		}
		nodeRecords = append(nodeRecords, record)
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
			strconv.Itoa(int(edge.Type)),
		}
		edgeRecords = append(edgeRecords, record)
	}
	edgeSave := csv.NewWriter(&edgeCSV)
	if err := edgeSave.WriteAll(edgeRecords); err != nil {
		panic(err)
	}
	edgeSave.Flush()

	return nodeCSV.Bytes(), edgeCSV.Bytes()
}
