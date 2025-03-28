package progcovergraph

import (
	"fmt"

	"github.com/google/syzkaller/pkg/covergraph"
	"github.com/google/syzkaller/pkg/proggraph"
	"github.com/google/syzkaller/prog"
)

type ProgCoverGraphGenerator struct {
	kernelCFG       *covergraph.KernelCFG
	shortcutEdgeHop int
}

type ProgCoverGraphGeneratorConfig struct {
	ChildBlockDict  string
	BlockASMDict    string
	BlockFuncDict   string
	ASMTokenDict    string
	ShortcutEdgeHop int
}

func InitProgCoverGraphGenerator(config *ProgCoverGraphGeneratorConfig) *ProgCoverGraphGenerator {
	kernelCFG := &covergraph.KernelCFG{}
	kernelCFG.LoadChildBlockDict(config.ChildBlockDict)
	kernelCFG.LoadBlockASM(config.BlockASMDict)
	kernelCFG.LoadBlockFunc(config.BlockFuncDict)
	kernelCFG.LoadASMTokenDict(config.ASMTokenDict)
	return &ProgCoverGraphGenerator{
		kernelCFG: kernelCFG,
		shortcutEdgeHop: config.ShortcutEdgeHop,
	}
}

func (gen *ProgCoverGraphGenerator) Generate(prog *prog.Prog, progCover *covergraph.ProgCover) (*ProgCoverGraphData, error) {
	// =========================================================================
	// Generate the cover graph
	// =========================================================================
	covergraph := covergraph.InitCoverGraph()
	flowAnalysisResult := gen.kernelCFG.ExtractFlow(progCover, gen.shortcutEdgeHop)
	coveredFlowList := flowAnalysisResult.CoveredFlowList
	uncoveredFlowList := flowAnalysisResult.UncoveredFlowList
	shortcutFlowList := flowAnalysisResult.ShortcutFlowList
	entryBlockNodeIDList := flowAnalysisResult.EntryBlockNodeIDList
	lastBlockNodeIDList := flowAnalysisResult.LastBlockNodeIDList

	covergraph.SetEntryBlockNodeIDList(entryBlockNodeIDList)
	covergraph.SetLastBlockNodeIDList(lastBlockNodeIDList)
	covergraph.AddFlow(coveredFlowList)
	covergraph.AddFlow(uncoveredFlowList)
	covergraph.AddFlow(shortcutFlowList)
	
	if covergraph.IsEmpty() {
		return nil, fmt.Errorf("cannot create covergraph")
	}
	// =========================================================================
	// Generate the prog graph
	// =========================================================================
	proggraph := proggraph.GenerateGraph(prog)

	// =========================================================================
	// Connect two graphs 
	// =========================================================================
	progCoverGraph := GenerateGraph(proggraph, covergraph)
	return progCoverGraph.Export(gen.kernelCFG.ASMByBlock, gen.kernelCFG.ASMTokenDict), nil
}
