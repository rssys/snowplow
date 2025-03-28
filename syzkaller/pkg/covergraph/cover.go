package covergraph

import (
	"github.com/google/syzkaller/pkg/log"
)

type CallCover struct {
	Trace []uint64
}

type ProgCover struct {
	CallList []CallCover
}

type FlowAnalysisResult struct {
	CoveredFlowList      []Flow
	UncoveredFlowList    []Flow
	ShortcutFlowList     []Flow
	EntryBlockNodeIDList []NodeID
	LastBlockNodeIDList  []NodeID
}

// Extract the covered, uncovered and shortcut flow from the covered control relations
// along with entry block node ID list
func (cfg *KernelCFG) ExtractFlow(progCover *ProgCover, shortcutDist int) FlowAnalysisResult {
	var coveredFlowList []Flow
	var uncoveredFlowList []Flow
	var shortcutFlowList []Flow
	var coveredBlockSet map[uint64]bool
	var entryBlockNodeIDList []NodeID
	var exitBlockNodeIDList []NodeID

	// get the overall coverage
	coveredBlockSet = make(map[uint64]bool)
	for _, callCover := range progCover.CallList {
		for _, block := range callCover.Trace {
			coveredBlockSet[block] = true
		}
	}

	// 1. extract the covered control flow
	lastBlockInPrevCall := uint64(0)
	for _, callCover := range progCover.CallList {
		// add a dummy block if no blocks are traced for this call
		if len(callCover.Trace) == 0 {
			callCover.Trace = append(callCover.Trace, 0xffffffff)
		}
		// add the entry block ID to the list
		entryBlockNodeID := NodeID{
			BlockAddr: callCover.Trace[0],
			Type:      NodeTypeCovered,
		}
		entryBlockNodeIDList = append(entryBlockNodeIDList, entryBlockNodeID)

		// add a special edge to connect two calls' coverage
		if lastBlockInPrevCall != 0 {
			srcNodeID := NodeID{
				BlockAddr: lastBlockInPrevCall,
				Type:      NodeTypeCovered,
			}
			dstNodeID := NodeID{
				BlockAddr: callCover.Trace[0],
				Type:      NodeTypeCovered,
			}
			flow := Flow{
				Type:      EdgeTypeCallConnect,
				SrcNodeID: srcNodeID,
				DstNodeID: dstNodeID,
			}
			coveredFlowList = append(coveredFlowList, flow)
		}

		// Add the only block in the node list as the exit node,
		// since we will skip the following traversal if there is only one block
		if len(callCover.Trace) == 1 {
			exitBlockNodeID := NodeID{
				BlockAddr: callCover.Trace[0],
				Type:      NodeTypeCovered,
			}
			exitBlockNodeIDList = append(exitBlockNodeIDList, exitBlockNodeID)
		}

		foundExitBlock := false
		// Introduce the shortcut
		currShortcutDistance := shortcutDist
		lastShortcutBlock := callCover.Trace[0]
		lastBlock := lastShortcutBlock
		for idx, block := range callCover.Trace[1:] {
			srcNodeID := NodeID{
				BlockAddr: lastBlock,
				Type:      NodeTypeCovered,
			}
			dstNodeID := NodeID{
				BlockAddr: block,
				Type:      NodeTypeCovered,
			}
			flow := Flow{
				Type:      EdgeTypeCovered,
				SrcNodeID: srcNodeID,
				DstNodeID: dstNodeID,
			}
			coveredFlowList = append(coveredFlowList, flow)

			// Check and add the shortcut
			currShortcutDistance--
			if currShortcutDistance == 0 {
				lastShortcutBlockID := NodeID{
					BlockAddr: lastShortcutBlock,
					Type:      NodeTypeCovered,
				}
				flow := Flow{
					Type:      EdgeTypeShortcut,
					SrcNodeID: lastShortcutBlockID,
					DstNodeID: dstNodeID,
				}
				shortcutFlowList = append(shortcutFlowList, flow)
				currShortcutDistance = shortcutDist
				lastShortcutBlock = block
			}

			// Check and add the exit block
			if !foundExitBlock {
				// If this is the last block and we haven't found the exit block, take this last block as the exit block.
				// Note that since we started the for loop from the callCover.Trace[1] while the idx starts from 0,
				// the last block idx should be len(callCover.Trace)-2
				if idx == len(callCover.Trace)-2 {
					foundExitBlock = true
					exitBlockNodeID := NodeID{
						BlockAddr: block,
						Type:      NodeTypeCovered,
					}
					exitBlockNodeIDList = append(exitBlockNodeIDList, exitBlockNodeID)
					continue
				}

				// Check if the block is in the block function name dictionary,
				// if cannot find the function name, skip this block
				if _, exists := cfg.funcByBlock[block]; !exists {
					log.Logf(3, "cannot find the function name for block: %x", block)
					continue
				}
				// Generally, we will take the previous block of the first block that belongs to the function "exit_to_user_mode_prepare"
				// or "fpregs_assert_state_consistent" as the exit block.
				// Check if current block belongs to the function "exit_to_user_mode_prepare" or "fpregs_assert_state_consistent",
				// if so, we will take its previous block as the exit block
				if cfg.funcByBlock[block] == "exit_to_user_mode_prepare" || cfg.funcByBlock[block] == "fpregs_assert_state_consistent" {
					foundExitBlock = true
					exitBlockNodeID := NodeID{
						BlockAddr: lastBlock,
						Type:      NodeTypeCovered,
					}
					exitBlockNodeIDList = append(exitBlockNodeIDList, exitBlockNodeID)
				}
			}

			// Update lastBlock lastly
			lastBlock = block
		}
		lastBlockInPrevCall = lastBlock
	}

	// 2. extract the uncovered control flow
	for coveredBlock := range coveredBlockSet {
		reachableChildBlockSet, exists := cfg.ChildBlockByBlock[coveredBlock]
		if !exists {
			log.Logf(3, "cannot find the parent block in the CFG: %x", coveredBlock)
			reachableChildBlockSet, exists = cfg.ChildBlockByBlock[coveredBlock-5]
			if !exists {
				log.Logf(3, "cannot find the parent block in the CFG: %x", coveredBlock-5)
				continue
			}
		}
		srcNodeID := NodeID{
			BlockAddr: coveredBlock,
			Type:      NodeTypeCovered,
		}
		for possibleChildBlock := range reachableChildBlockSet {
			// skip the already-covered control flows by checking the coverage
			if _, exists := coveredBlockSet[possibleChildBlock]; exists {
				continue
			}
			// NOTE: this check may be unnecessary after the Angr patching?
			if _, exists := coveredBlockSet[possibleChildBlock+5]; exists {
				continue
			}
			dstNodeID := NodeID{
				BlockAddr: possibleChildBlock,
				Type:      NodeTypeUncovered,
			}
			flow := Flow{
				Type:      EdgeType(EdgeTypeUncovered),
				SrcNodeID: srcNodeID,
				DstNodeID: dstNodeID,
			}
			uncoveredFlowList = append(uncoveredFlowList, flow)
		}
	}
	return FlowAnalysisResult{
		CoveredFlowList:      coveredFlowList,
		UncoveredFlowList:    uncoveredFlowList,
		ShortcutFlowList:     shortcutFlowList,
		EntryBlockNodeIDList: entryBlockNodeIDList,
		LastBlockNodeIDList:  exitBlockNodeIDList,
	}
}
