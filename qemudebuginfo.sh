#!/bin/bash
export HOST=${HOST:-$(./default-host.sh)}
echo "Starting debugging session"
qemu-system-$(./target-triplet-to-arch.sh $HOST) -cdrom Spartix.iso -d int -m 1024M -monitor stdio -boot d -s
echo "Output written to qemudbg.log"
