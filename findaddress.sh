#!/bin/bash

echo "Finding debugging information about" "$1"
echo "Using addr2line"
addr2line -e kernel/vmspartix $1
echo "End of addr2line output."
echo "Grepping through objdump"
objdump -M intel -d kernel/vmspartix | grep $1
echo "End of output."
echo "Done."
