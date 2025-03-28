#!/bin/bash

#$1 is the filename of the kernel address file
cat $1 | addr2line -e $VMLINUX_FILE -afp > $1.result
