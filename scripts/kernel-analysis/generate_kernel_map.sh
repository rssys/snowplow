#!/bin/bash

# Usage
# ./generate-kernel-map.sh ./compiled-linux-kernel/vmlinux

VMLINUX_FILE=$1
export VMLINUX_FILE
CONCURRENCY_LEVEL=48

if [ -z "$2" ]; then
	SAVE_DIR=./tmp/
else
	SAVE_DIR=$2
fi

mkdir -p $SAVE_DIR

echo "step-1. generating the kernel disassembly using objdump -d vmlinux"
objdump -d $VMLINUX_FILE > $SAVE_DIR/vmlinux.dis

echo "step-2. extracting addresses of kernel instructions from the diassembly"
grep '^ffffffff[0-9a-z]\{8\}:' $SAVE_DIR/vmlinux.dis | cut -d ':' -f 1 > $SAVE_DIR/vmlinux.addresses

echo "step-3. run addr2line in parallel"
split -n l/100 $SAVE_DIR/vmlinux.addresses $SAVE_DIR/vmlinux.addresses.split.
ls $SAVE_DIR/vmlinux.addresses.split.[a-z][a-z] | xargs -n 1 -P $CONCURRENCY_LEVEL  ./generate_kernel_map_worker.sh
ls $SAVE_DIR/vmlinux.addresses.split.[a-z][a-z].result | sort | xargs cat > $SAVE_DIR/vmlinux.map

rm $SAVE_DIR/vmlinux.addresses.split*
