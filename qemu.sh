#!/bin/sh
set -e
. ./iso.sh

qemu-system-$(./target-triplet-to-arch.sh $HOST) -cdrom Spartix.iso -drive file=hdd.img,format=raw,index=0,media=disk -m 1024M -monitor stdio  -boot d --enable-kvm --no-reboot --no-shutdown
