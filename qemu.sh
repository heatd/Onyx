#!/bin/sh
set -e
. ./iso.sh

qemu-system-$(./target-triplet-to-arch.sh $HOST) -cdrom Spartix.iso -m 1024M -monitor stdio -d cpu_reset  -boot d -enable-kvm
