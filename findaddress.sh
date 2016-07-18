#!/bin/bash

echo "Finding debugging information about" "$1"
echo "Using addr2line"
addr2line -e kernel/vmspartix-0.1-gen64 $1
echo "End of addr2line output."
echo "Grepping through objdump"
objdump -d kernel/vmspartix-0.1-gen64 | grep $1
echo "End of output."
echo "Done."
