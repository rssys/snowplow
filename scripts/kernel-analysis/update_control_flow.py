import pickle
import re
import json
import argparse

# input file path
CFG_PATH=None
VMLINUX_DIS_PATH=None
INDIRECT_CALLS_PATH=None

# Trace_pc function address
TRACE_PC_ADDR=None

# output block calling dict path
UNMODIFIED_BLK_DICT_PATH=None
MODIFIED_BLK_DICT_PATH=None
PICKLE_UNMODIFIED_BLK_DICT_PATH=None
PICKLE_MODIFIED_BLK_DICT_PATH=None
BLOCK_ASM_PATH=None
BLOCK_FUNC_PATH=None
RESULT_PATH=None

"""
Find the address of TRACE_PC_ADDR from the vmlinux disassembly
"""
def get_KCOV(vmlinux_dis_path):
    kcov_addr = None
    with open(vmlinux_dis_path, "r") as f:
        for line in f:
            if "call" in line and "<__sanitizer_cov_trace_pc>" in line:
                kcov_addr = int(line.split(" ")[-2].strip(), 16)
                break
    if kcov_addr is None:
        print("Cannot find kcov address")
        exit(1)
    global TRACE_PC_ADDR
    TRACE_PC_ADDR = kcov_addr
    print(f"TRACE_PC_ADDR is set to: {hex(TRACE_PC_ADDR)}")

"""
Determine if the instruction is a call to the __sanitizer_cov_trace_pc() function
"""
def is_call_KCOV_inst(inst):
    if "call" in inst and hex(TRACE_PC_ADDR)[2:] in inst and "<__sanitizer_cov_trace_pc>" in inst:
        return True
    return False

"""
Determine if the instruction is a call/jump to the __kasan_* function
"""
def is_transfer_KASAN_inst(inst):
    if ("__kasan_" in inst and "call" in inst) or ("__kasan_" in inst and "jmp" in inst and "+" not in inst):
        return True
    return False

"""
Load the cfg
"""
def load_cfg(filepath):
    print("Loading CFG...")
    cfg = None
    with open(filepath, "rb") as tmp_f:
        cfg = pickle.load(tmp_f)
    return cfg
"""
Generate the mapping from binary address to the function name
"""
def get_addr2func(vmlinux_dis_path):
    addr2func = {}
    with open(vmlinux_dis_path, "r") as f:
        curr_func = None
        for line in f:
            if ">:" in line and len(line) > 16:
                match = re.search(r'<(.*?)>', line)
                if match:
                    curr_func = match.group(1)
            elif len(line) > 16 and line[16] == ":" and curr_func:
                addr = int(line[:16], 16)
                addr2func[addr] = curr_func

    return addr2func
"""
Check if there are overlapping blocks
"""
def check_overlapping(cfg):
    print("Checking overlapping blocks...")
    node_list = list(cfg.graph.nodes)
    block_address = set()
    for node in node_list:
        start = node.addr
        block_address.add(start)
    assert(len(block_address) == len(node_list))
"""
Get the blocks for each function: dict[func_name] = [block1, block2, ...
"""
def func_blocks(cfg, addr2func):
    node_list = list(cfg.graph.nodes)
    block_info = {}
    for node in node_list:
        start = node.addr
        # the binary addresses in the Angr CFG may not strictly aligned with instruction addresses in the vmlinux disassembly
        if start not in addr2func:
            print(f"{hex(start)} not found in addr2func")
            continue
        func = addr2func[start]
        if func not in block_info:
            block_info[func] = []
        block_info[func].append(node)
    for func in block_info:
        # sort the node by their address
        block_info[func] = sorted(block_info[func], key=lambda x: x.addr)

    return block_info

"""
get the mapping from addr -> disassembly instruction
"""
def get_addr2inst(vmlinux_dis_path):
    addr2inst = {}
    with open(vmlinux_dis_path, "r") as f:
        for line in f:
            if len(line) < 17 or line[16] != ":":
                continue

            addr = int(line[:16], 16)
            inst = line

            addr2inst[addr] = inst
    return addr2inst
"""
get the original (unmodified) block calling dict
"""
def get_original_calling_dict(cfg):
    node_list = list(cfg.graph.nodes)
    block_calling_dict = {}
    for node in node_list:
        child_node_list = list(node.successors_and_jumpkinds())
        parent_block_addr = node.addr
        if parent_block_addr not in block_calling_dict:
            block_calling_dict[parent_block_addr] = set()
        for child_node in child_node_list:
            if child_node[1] == "Ijk_Ret":
                continue
            block_calling_dict[parent_block_addr].add(child_node[0].addr)
    return block_calling_dict
"""
generate the block be called list from a give block calling dict
suppose block(X) calls block(Y),(i.e. block_calling_dict[X] = [Y,...]), then we will have block_called_dict[Y] = {X, ...} 
"""
def get_called_dict(block_calling_dict):
    called_dict = {}
    for parent_block in block_calling_dict:
        assert(type(block_calling_dict[parent_block]) == set)
        for child_block in block_calling_dict[parent_block]:
            if child_block not in called_dict:
                called_dict[child_block] = set()
            called_dict[child_block].add(parent_block)
    return called_dict
"""
Find the next block that is not kcov in the current function
"""
def find_next_nonkcov_block(curr_block, block_info, addr2inst, addr2func):
    func_name = addr2func[curr_block.addr]
    result_block = None
    for block in block_info[func_name]:
        if block.addr <= curr_block.addr:
            continue
        if len(block.instruction_addrs) == 0:
            continue
        if is_call_KCOV_inst(addr2inst[block.instruction_addrs[0]]):
            continue
        result_block = block
        break
    # we cannot make the following assertion, because `call kcov_trace_pc` maybe the last block of the function 
    # assert(result_block is not None)
    if result_block is None:
        print(f"for curr block {hex(curr_block.addr)}, no next block doesn't start with kcov can be found within the function")
    return result_block

"""
Find the names of the functions that are not instrumented by KCOV
"""
def get_uninstrumented_funcs(vmlinux_dis_path, block_info, block_calling_dict, addr2func):
    uninstrumented_funcs = set()
    uninstrumented = False
    prev_func = None
    with open(vmlinux_dis_path, "r") as f:
        for line in f:
            if ">:" in line and len(line) > 16:
                match = re.search(r'<(.*?)>', line)
                if match:
                    if uninstrumented and prev_func is not None:
                        uninstrumented_funcs.add(prev_func)
                    prev_func = match.group(1)
                    uninstrumented = True
            elif len(line) > 16 and "__sanitizer_cov_trace_pc" in line:
                uninstrumented = False
    assert("__sanitizer_cov_trace_pc" not in uninstrumented_funcs)
    return uninstrumented_funcs

"""
Case 0:
* Angr reports: Block(X) -> Func(Y), where Func(Y) is not instrumented by KCOV
* KCOV reports: Block(X) -> Block(Z), where Block(Z) is the return block after Func(Y)

Fix:
(1) Find the funcs that are not instrumented by KCOV
(2) For each block that ends with `call funcX` and `funcX` is not instrumented by KCOV,
    add the control flow edge of Block(X) -> Block(Z),
    where Block(Z) is the next block after Block(X) within the same function

After this fix, each `call` control flow edge to an uninstrumented function will be redirected to the next block after it

Note that if:
(1) Block(Z) is `call kcov_trace_pc`, then we will have case 2 to handle this
(2) Block(Z) is an uninstrumented block, then we will have case 3 to handle this
"""
def fix_case0(block_info, block_calling_dict, addr2func, addr2inst):
    assert block_calling_dict is not None
    result_calling_dict = block_calling_dict.copy()
    # get the function list of uninstrumented functions
    uninstrumented_funcs = get_uninstrumented_funcs(VMLINUX_DIS_PATH, block_info, block_calling_dict, addr2func)
    counter = 0

    for func in block_info:
        for block in block_info[func]:
            assert(block.instruction_addrs != 0)
            assert(block.instruction_addrs[-1] in addr2inst)
            # get the last instruction fo this block
            last_inst = addr2inst[block.instruction_addrs[-1]]
            # check if the last instruction is a call to a function
            if "callq" in last_inst and "<" in last_inst and ">" in last_inst:
                # try to get the function name
                match = re.search(r'<(.*?)>', last_inst)
                if match:
                    called_func = match.group(1)
                    # if the called function is uninstrumented, then we need to add the control flow edge
                    if called_func in uninstrumented_funcs:
                        next_block_addr = block.addr + block.size
                        # add an edge of current block -> next block within the same function 
                        if addr2func[next_block_addr] == func:
                            result_calling_dict[block.addr].add(next_block_addr)
                            counter += 1
    
    print(f"Added {counter} edges for case 0")
    return result_calling_dict

"""
Case 1: 
* Angr reports: Block(X) -> Block(Y), where Block(X) ends with `call kcov_trace_pc`, so Block(Y) is `kcov_trace_pc`
* KCOV reports: Block(X) -> Block(Z), where Block(Z) is the next block after Block(Y)

Fix:
(1) remove the control flow edge of Block(X) -> Block(Y), where Block(Y) is actually `kcov_trace_pc` function
(2) add the control flow edge of Block(X) -> Block(Z), where Block(Z) is the next block after Block(Y) within the same function

After this fix, each the control flow from a block that ends with `call kcov_trace_pc` will be redirected to the next non-kcov block after it
"""
def fix_case1(block_info, block_calling_dict, addr2inst, addr2func):
    assert block_calling_dict is not None
    result_calling_dict = block_calling_dict.copy()
    for func in block_info:
        for block in block_info[func]:
            # assert the block cannot be empty
            assert(block.instruction_addrs !=0)
            # get the last instruction string of this block
            assert(block.instruction_addrs[-1] in addr2inst)
            last_inst = addr2inst[block.instruction_addrs[-1]]
            # skip the current block if it doesn't end with `call kcov_trace_pc`
            if not is_call_KCOV_inst(last_inst):
                continue
            # make sure the only child of this block is KCOV
            assert(len(block_calling_dict[block.addr]) == 1)
            assert(TRACE_PC_ADDR in block_calling_dict[block.addr])
            next_valid_block = find_next_nonkcov_block(block, block_info, addr2inst, addr2func)
            # skip if we cannot find a next non `call kcov_trace_pc` block within the same function
            if next_valid_block == None:
                continue
            result_calling_dict[block.addr].remove(TRACE_PC_ADDR)
            result_calling_dict[block.addr].add(next_valid_block.addr)
    return result_calling_dict
    
"""
Case 2:
* Angr reports: Block(X) -> Block(Y), where Block(Y) only contains `call kcov_trace_pc`
* KCOV reports: Block(X) -> Block(Z), where Block(Z) is the next block after Block(Y)

Fix:
(1) Find each block that only contains `call kcov_trace_pc`, denote it as Block(Y)
(2) Find the caller(s) of Block(Y), denote it as Block(X)
(3) Remove the control flow edge of Block(X) -> Block(Y)
(4) Add the control flow edge of Block(X) -> Block(Z), where Block(Z) is the next block after Block(Y) within the same function

After this fix, each the control flow to a block that only contains `call kcov_trace_pc` will be redirected to the next non-kcov block after it
"""
def fix_case2(block_info, block_calling_dict, addr2inst, addr2func):
    assert block_calling_dict is not None
    # block_called_dict contains the mapping fom (callee) block to the blocks (caller) that call it
    block_called_dict = get_called_dict(block_calling_dict)
    result_calling_dict = block_calling_dict.copy()

    for func in block_info:
        for block in block_info[func]:
            # 0. make sure this block only contain one instruction
            if len(block.instruction_addrs) != 1:
                continue
            # 1. make sure the only instruction is `call kcov_trace_pc`
            if not is_call_KCOV_inst(addr2inst[block.instruction_addrs[0]]):
                continue
            # 2. update the calling dict
            # skip if this block is never called by any other block
            if block.addr not in block_called_dict:
                continue
            next_valid_block = find_next_nonkcov_block(block, block_info, addr2inst, addr2func)
            if next_valid_block == None:
                continue
            assert(type(block_called_dict[block.addr]) == set)
            for caller in block_called_dict[block.addr]:
                assert(block.addr in result_calling_dict[caller])
                result_calling_dict[caller].remove(block.addr)
                result_calling_dict[caller].add(next_valid_block.addr)
    return result_calling_dict

"""
Case 3:
* This is the 2-hops case, where Block(X) -> Block(Y) -> Block(Z), where Block(Z) is `call kcov_trace_pc`
    suppose Block(Y) doesn't contain `call kcov_trace_pc`, and it's previous instruction is not `call kcov_trace_pc`.
    Since Block(Y) is not instrumented, KCOV will ignore this block, and follow the control flow to mark the next instrumented block as Block(X)'s child.
* Angr reports Block(X) -> Block(Y), Block(Y) -> Block(Z)
* KCOV reports Block(X) -> Block(F), where Block(F) is the next block after Block(Z)

Fix:
    Note that we won't verify if Block(Z) is instrumented or not for simplicity.
(1): Find each block that doesn't contain `call kcov_trace_pc`, and its previous instruction is not `call kcov_trace_pc`, denote it as Block(Y)
(2): Find the caller(s) of Block(Y), denote it as Block(X)
(3): Find the children of Block(Y), denote it as Block(Z)
(4): Remove the control flow edge of Block(X) -> Block(Y)
(5): Add the control flow edge of Block(X) -> Block(Z)

Note that in the unmodified control flow, if we have Block(Y) -> Block(Z) and Block(Z) is `call kcov_trace_pc`, then after fixing case 2, Block(Z) would be the next non-kcov block it.
After this fix, each control flow edge to a uninstrumented block will skip this block and go to its children.
"""
def fix_case3(block_info, block_calling_dict, addr2inst):
    assert block_calling_dict is not None
    # block_called_dict contains the mapping fom (callee) block to the blocks (caller) that call it
    block_called_dict = get_called_dict(block_calling_dict)
    result_calling_dict = block_calling_dict.copy()

    for func in block_info:
        for block in block_info[func]:
            # 0. make sure this block doesn't contain any `kcov` instruction
            assert(block.instruction_addrs != 0)
            if is_call_KCOV_inst(addr2inst[block.instruction_addrs[-1]]):
                continue
            # 1. make sure the last instruction of previous block is not `call kcov_trace_pc`
            addr_of_prev_inst = block.addr - 5
            if addr_of_prev_inst in addr2inst and is_call_KCOV_inst(addr2inst[addr_of_prev_inst]):
                continue
            # 2. find the caller(s) to the current block
            if block.addr not in block_called_dict:
                continue
            assert(type(block_called_dict[block.addr]) == set)
            for caller in block_called_dict[block.addr]:
                # only consider the 2 hops
                # 3. update the calling dict
                assert(block.addr in result_calling_dict[caller])
                result_calling_dict[caller].remove(block.addr)
                # add the children of current block to the caller
                for child in block_calling_dict[block.addr]:
                    result_calling_dict[caller].add(child)
    return result_calling_dict

"""
Case 4: 
* Suppose Block(X) -> Block(Y), where Block(Y) ends with `call kcov_trace_pc`, and its previous intruction is not `call kcov_trace_pc` (i.e. Block(Y) is uninstrumented)
* Suppose Block(Z) is the next non-kcov block after Block(Y) within the same function
* Angr reports: Block(X) -> Block(Y), Block(Y) -> kcov_trace_pc function
* KCOV reports: Block(X) -> Block(Z)
 
Fix:
(1) Find each block that ends with `call kcov_trace_pc` and its previous instruction is not `call kcov_trace_pc`, denote it as Block(Y)
(2) Find the caller(s) of Block(Y), denote it as Block(X)
(3) Find the next non-kcov block after Block(Y), denote it as Block(Z)
(4) Remove the control flow edge of Block(X) -> Block(Y)
(5) Add the control flow edge of Block(X) -> Block(Z)

* Suppose Block(Y) ends with `call kcov_trace_pc`, and its previous instruction is not `call kcov_trace_pc` (i.e. Block(Y) is uninstrumented)
    case 1 handles Block(Y) as a caller, while this case handles Block(Y) as a children.
Note that after fixing case 1, Block(Z) would be the children of Block(Y), so we can just replace Block(Y) with its children when updating the calling dict.
"""
def fix_case4(block_info, block_calling_dict, addr2inst):
    assert block_calling_dict is not None
    block_called_dict = get_called_dict(block_calling_dict)
    result_calling_dict = block_calling_dict.copy()
    for func in block_info:
        for block in block_info[func]:
            # 0. make sure the block ends with `call kcov_trace_pc`
            assert(block.instruction_addrs != 0)
            assert(block.instruction_addrs[-1] in addr2inst)
            last_inst = addr2inst[block.instruction_addrs[-1]]
            if not is_call_KCOV_inst(last_inst):
                continue
            # 1. make sure the block contains other instructions than `callq kcov`
            if len(block.instruction_addrs) == 1:
                continue
            # 2. make sure the last instruction of previous block is not `call kcov`
            addr_of_prev_inst = block.addr - 5
            if addr_of_prev_inst in addr2inst and is_call_KCOV_inst(addr2inst[addr_of_prev_inst]):
                continue                
            # 3. find the caller(s) to the current block
            if block.addr not in block_called_dict:
                continue            
            assert(type(block_called_dict[block.addr]) == set)
            for caller in block_called_dict[block.addr]:
                # 4. update the calling dict
                assert(block.addr in result_calling_dict[caller])
                result_calling_dict[caller].remove(block.addr)
                # add the children of current block to the caller
                for child in block_calling_dict[block.addr]:
                    result_calling_dict[caller].add(child)
    return result_calling_dict

"""
Fix the control flow when KASAN is enbaled
* KASAN will insert some functions to check the memory access, such as `__kasan_check_read`, `__kasan_check_write`, etc.
* We need to fix the control flow to skip these functions

Fix:
(1) remove the control flow edge of Block(X) -> KASAN check function
(2) add the control flow edge of Block(X) -> next block after the KASAN check function within the same function

After this fix, the control flow from a block that ends with `callq __kasan_*` will be redirected to the next non-kcov block after it
"""
def fix_kasan(block_info, block_calling_dict, addr2inst, addr2func):
    assert block_calling_dict is not None
    result_calling_dict = block_calling_dict.copy()
    for func in block_info:
        for block in block_info[func]:
            # assert the block cannot be empty
            assert(block.instruction_addrs !=0)
            # get the last instruction string of this block
            assert(block.instruction_addrs[-1] in addr2inst)
            last_inst = addr2inst[block.instruction_addrs[-1]]
            # check if "__kasan_" is in the last instruction
            if is_transfer_KASAN_inst(last_inst):
                kasan_func_addr = int(last_inst.split(" ")[-2].strip(), 16)
                #print(f"Fixing call KASAN: {hex(block.addr)} -> {hex(kasan_func_addr)}")

                next_valid_block = find_next_nonkcov_block(block, block_info, addr2inst, addr2func)
                # skip if we cannot find a next non `call kcov_trace_pc` block within the same function
                if next_valid_block == None:
                    print(f"Cannot find the next valid block for {hex(block.addr)}")
                    continue
                
                #print(f"\tredirecting to: {hex(next_valid_block.addr)}")
                assert(kasan_func_addr in result_calling_dict[block.addr])
                result_calling_dict[block.addr].remove(kasan_func_addr)
                result_calling_dict[block.addr].add(next_valid_block.addr)

    return result_calling_dict

"""
Save the dict into a binary file with pickle
"""
def save_dict_pickle(filepath, block_calling_dict):
    with open(filepath, "wb") as tmp_f:
        pickle.dump(block_calling_dict, tmp_f, pickle.HIGHEST_PROTOCOL)

"""
Save the block calling dict to a file with plain text
"""
def save_dict_plaintext(filepath, block_calling_dict, type):
    with open(filepath, "w") as f:
        # save the dict as: caller callee1, callee2, ...
        for caller in block_calling_dict:
            callees = block_calling_dict[caller]
            callees_str = ",".join([hex(callee) for callee in callees])
            print(f"{hex(caller)}: {callees_str} {type}", file = f)

"""
Generate the final result of the patched Angr CFG
"""
def gen_result(filepath, unmodified_block_calling_dict, modified_block_calling_dict):
    # assert(len(unmodified_block_calling_dict) == len(modified_block_calling_dict))
    # TODO: add modified or not tag later for graph generation
    with open(filepath, "w") as f:
        for caller in modified_block_calling_dict:
            if caller not in unmodified_block_calling_dict:
                callees_str = " ".join([hex(callee) for callee in modified_block_calling_dict[caller]])
                # print(f"{hex(caller)} {callees_str} modified", file = f)
                print(f"{hex(caller)} {callees_str}", file = f)
                continue

            assert(caller in unmodified_block_calling_dict)
            assert(caller in modified_block_calling_dict)
            unmodified_callees = unmodified_block_calling_dict[caller]
            modified_callees = modified_block_calling_dict[caller]
            edge_type = "unmodified"
            if unmodified_callees != modified_callees:
                edge_type = "modified"
                # print(f"[modified] caller: {hex(caller)}")
        
            callees_str = " ".join([hex(callee) for callee in modified_callees])
            # print(f"{hex(caller)}: {callees_str} {edge_type}", file = f)
            print(f"{hex(caller)} {callees_str}", file = f)

"""
Add indirect calls to the Angr CFG
"""
def add_indirect_calls(block_calling_dict):
    assert block_calling_dict is not None
    # load indirect calls
    indirect_calls = None
    with open(INDIRECT_CALLS_PATH, 'r') as f:
        indirect_calls = json.load(f)
    assert isinstance(indirect_calls, dict), "indirect_calls should be a dict"

    # add indirect calls to block_calling_dict
    result_block_calling_dict = block_calling_dict.copy()
    for caller in indirect_calls:
        caller_int = int(caller, 16)
        callees_int = [int(callee, 16) for callee in indirect_calls[caller]]
        if caller_int not in result_block_calling_dict:
            result_block_calling_dict[caller_int] = set()
        for callee in callees_int:
            result_block_calling_dict[caller_int].add(callee)
    return result_block_calling_dict

"""
Parse the arguments and set the global values
"""
def parse_arguments():
    parser = argparse.ArgumentParser(description='Update the Angr CFG control flow')
    parser.add_argument('--cfg', type=str, required=True, help='The path to the Angr CFG pickle file')
    parser.add_argument('--vmlinux_dis', type=str, required=True, help='The path to the vmlinux disassembly file')
    parser.add_argument('--indirect_calls', type=str, default=None, help='(Optional) The path to the indirect calls json file')
    parser.add_argument('--outdir', type=str, required=True, help='The output directory for patched block calling dict')

    # get the arguments
    args = parser.parse_args()

    # set the global values
    global CFG_PATH, VMLINUX_DIS_PATH, INDIRECT_CALLS_PATH
    global UNMODIFIED_BLK_DICT_PATH, MODIFIED_BLK_DICT_PATH, PICKLE_UNMODIFIED_BLK_DICT_PATH, PICKLE_MODIFIED_BLK_DICT_PATH, RESULT_PATH, BLOCK_ASM_PATH, BLOCK_FUNC_PATH
    CFG_PATH = args.cfg
    VMLINUX_DIS_PATH = args.vmlinux_dis
    INDIRECT_CALLS_PATH = args.indirect_calls

    UNMODIFIED_BLK_DICT_PATH = args.outdir + "/block-calling-dict.unmodified"
    MODIFIED_BLK_DICT_PATH = args.outdir + "/block-calling-dict.modified"
    PICKLE_UNMODIFIED_BLK_DICT_PATH = args.outdir + "/pickle-block-calling-dict.unmodified"
    PICKLE_MODIFIED_BLK_DICT_PATH = args.outdir + "/pickle-block-calling-dict.modified"
    RESULT_PATH = args.outdir + "/block-calling-dict.result"
    BLOCK_ASM_PATH = args.outdir + "/block-asm-dict"
    BLOCK_FUNC_PATH = args.outdir + "/block-func-dict"

"""
Tokenize the instruction assembly code. For example:
"nopw   %cs:0x0(%rax,%rax,1)" --> "nopw %cs : immezero ( %rax , %rax , 1 )"
"""
def tokenize_asm(vmlinux_dis_path):
    ins_asm_dict = {}

    vmlinux_dis = []
    with open(vmlinux_dis_path, "r") as tmp_f:
        for line in tmp_f:
            vmlinux_dis.append(line.strip())

    for line in vmlinux_dis:
        # skip the non-assembly lines
        if len(line) < 17 or line[16] != ":":
            continue
        # i have verified # lines reached here equals to the length of vmlinux.map
        inst_addr = int(line[ : 16], 16)
        asm = line[40 : ].strip()
        # remove the asm comment
        if asm.find("#") != -1:
            asm = asm[ : asm.find("#")].strip()
        # strip the asm format
        asm = asm.replace("(", " ( ")
        asm = asm.replace(")", " ) ")
        asm = asm.replace(":", " : ")
        asm = asm.replace(",", " , ")
        # remove some spaces
        asm = asm.strip()
        asm = re.sub(" +", " ", asm)

        new_token_list = []
        if asm == "":
            new_token_list.append("asmpad")
        else:
            token_list = asm.split(" ")
            # remove the function name label
            remove_label = False
            for token_idx, token in enumerate(token_list):
                if token.startswith("<"):
                    assert token.endswith(">")
                    # assert this is the last token
                    assert token_idx == len(token_list) - 1
                    prior_token = token_list[token_idx - 1]
                    assert len(prior_token) == 16
                    remove_label = True
            if remove_label:
                token_list = token_list[ : -1]
            # replace values
            for token in token_list:
                assert len(token) != 0
                assert token.startswith("<") is False
                if token.startswith("$"):
                    if int(token[1 : ], 16) == 0:
                        new_token_list.append("immezero")
                    else:
                        new_token_list.append("imme")
                elif token.startswith("-"):
                    if int(token[ 1 : ], 16) == 0:
                        new_token_list.append("immezero")
                    else:
                        new_token_list.append("imme")
                elif token.startswith("*0x"):
                    if int(token[ 1 : ], 16) == 0:
                        new_token_list.append("immezero")
                    else:
                        new_token_list.append("imme")
                elif len(token) == 16:
                    if int(token, 16) == 0:
                        new_token_list.append("immezero")
                    else:
                        new_token_list.append("imme")
                elif token.startswith("0x"):
                    if int(token, 16) == 0:
                        new_token_list.append("immezero")
                    else:
                        new_token_list.append("imme")
                else:
                    new_token_list.append(token)
            #print(token_list, "-------->", new_token_list)
        new_asm = " ".join(new_token_list)
        ins_asm_dict[inst_addr] = new_asm
    return ins_asm_dict


"""
Get the assembly code for each block

Each line in the dict follow a specific format:
    BLOCK_ADDR ASM_STRING(lines are concatenated with " ; ")
For example:
    0xffffffff81000300 endbr64 ; mov %rdi,%rax ; jmpq ffffffff8222d310 <__x86_return_thunk> ;
"""
def get_block_asm(cfg, vmlinux_dis_path):
    ins_asm_dict = tokenize_asm(vmlinux_dis_path)

    block_asm_dict = {}
    node_list = list(cfg.graph.nodes)
    for node in node_list:
        block_start_addr = node.addr
        block_end_addr = node.addr + node.size
        ins_asm_list = []
        for ins_addr in range(block_start_addr, block_end_addr):
            if ins_addr in ins_asm_dict:
                ins_asm_list.append(ins_asm_dict[ins_addr])
        block_asm_dict[block_start_addr] = " ; ".join(ins_asm_list)
    global BLOCK_ASM_PATH
    with open(BLOCK_ASM_PATH, "w") as tmp_f:
        for block_addr in block_asm_dict:
            print(hex(block_addr), block_asm_dict[block_addr], file=tmp_f)
"""
Get the function name for each block

Each line in the dict follow a specific format:
    BLOCK_ADDR FUNC_NAME
For example:
    0xffffffff81000300 sev_verify_cbit
"""
def gen_block_func(cfg, addr2func):
    block_func_dict = {}
    node_list = list(cfg.graph.nodes)
    for node in node_list:
        block_start_addr = node.addr
        if block_start_addr not in addr2func:
            continue
        block_func = addr2func[block_start_addr]
        block_func_dict[block_start_addr] = block_func
    global BLOCK_FUNC_PATH
    with open(BLOCK_FUNC_PATH, "w") as tmp_f:
        for block_addr in block_func_dict:
            print(hex(block_addr), block_func_dict[block_addr], file=tmp_f)

"""
Main function
"""
def main():
    # parse the arguments
    parse_arguments()

    # load cfg
    cfg = load_cfg(CFG_PATH)
    
    # check overlapping blocks
    check_overlapping(cfg)

    # save the block asm dict
    get_block_asm(cfg, VMLINUX_DIS_PATH)

    # get the kcov address and call kcov string
    get_KCOV(VMLINUX_DIS_PATH)

    addr2inst = get_addr2inst(VMLINUX_DIS_PATH)
    addr2func = get_addr2func(VMLINUX_DIS_PATH)

    # save the block function dict
    gen_block_func(cfg, addr2func)

    block_info = func_blocks(cfg, addr2func)

    # generate the unmodified block calling dict
    block_calling_dict = get_original_calling_dict(cfg)
    save_dict_plaintext(UNMODIFIED_BLK_DICT_PATH, block_calling_dict, "unmodified")
    save_dict_pickle(PICKLE_UNMODIFIED_BLK_DICT_PATH, block_calling_dict)

    # add indirect calls if user specifies the indirect calls file
    if INDIRECT_CALLS_PATH is not None:
        block_calling_dict = add_indirect_calls(block_calling_dict)

    # add patches for 5 cases
    uninstrumented_funcs = get_uninstrumented_funcs(VMLINUX_DIS_PATH, block_info, block_calling_dict, addr2func)
    block_calling_dict = fix_kasan(block_info, block_calling_dict, addr2inst, addr2func)    
    block_calling_dict = fix_case0(block_info, block_calling_dict, addr2func, addr2inst)
    block_calling_dict = fix_case1(block_info, block_calling_dict, addr2inst, addr2func)
    block_calling_dict = fix_case2(block_info, block_calling_dict, addr2inst, addr2func)
    block_calling_dict = fix_case3(block_info, block_calling_dict, addr2inst)
    block_calling_dict = fix_case4(block_info, block_calling_dict, addr2inst)
    save_dict_plaintext(MODIFIED_BLK_DICT_PATH, block_calling_dict, "modified")
    save_dict_pickle(PICKLE_MODIFIED_BLK_DICT_PATH, block_calling_dict)

    # generate the final result
    modified_block_calling_dict = block_calling_dict
    unmodified_block_calling_dict = get_original_calling_dict(cfg)

    gen_result(RESULT_PATH, unmodified_block_calling_dict, modified_block_calling_dict)

if __name__ == '__main__':
    main()