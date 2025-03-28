## Prerequisites
- `angr==9.2.85`
- compiled kernel

## Kernel addr2line
The script `generate_kernel_map.sh` generates the mapping from each instruction address in vmlinux to the correspoding source code location.
```bash
./generate_kernel_map.sh $VMLINUX_FILEPATH
```
$VMLINUX_FILEPATH is the path of the compiled kernel binary vmlinux.


## Kernel CFG
The script `generate_kernel_cfg.py` generates the control flow graph (CFG) using Angr static analysis.
```bash
./generate_kernel_cfg.py $VMLINUX_FILEPATH
```
A python pickle of the CFG object named as `cfg-pickle` will be generated.


## Update Angr CFG Control Flow
The script `update_control_flow.py` will patch the Angr CFG so that we can analyze the KCOV trace accurately.
```bash
python update_control_flow.py --cfg $CFG --vmlinux_dis $VMLINUX_DIS --indirect_calls $INDIRECT_CALLS --outdir $OUTDIR
```
You can run `python update_control_flow.py --help` for more details about each argument. Note `--indirect_calls` is deprecated.

A file named `block-calling-dict.result` under `$OUTDIR`, each line represents all the edges from a parent block to its children: `PARENT_BLOCK_ADDR CHILD_BLOCK_ADDR_1 CHILD_BLOCK_ADDR_2 ...`.

Also, this script will generate a file called `block-asm-dict` under `$OUTDIR`, which stores the mapping from each block address to the assembly strings of its instructions.
Each line follows the format of `BLOCK_ADDR ASM_STRING`(lines are concatenated with `' ; '`). This file is used to assist ML model to better understand the basic blocks.
