#!/bin/sh
set -e
. ./iso.sh

qemu-system-$(./target-triplet-to-arch.sh $HOST) -s -cdrom Spartix.iso -drive file=hdd.img,format=raw,index=0,media=disk -m 1024M -monitor stdio  -boot d -d int --no-reboot --no-shutdown
