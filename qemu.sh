#!/bin/sh
set -e
. ./iso.sh

qemu-system-$(./target-triplet-to-arch.sh $HOST) -s -cdrom Onyx.iso -drive file=hdd.img,format=raw,media=disk -m 100M -monitor stdio  -boot d -net nic,model=e1000 -net dump,file=net.pcap -net user --enable-kvm -smp 4 -cpu SandyBridge,+avx
