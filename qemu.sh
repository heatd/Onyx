#!/bin/sh
set -e
. ./iso.sh

/usr/local/bin/qemu-system-$(./target-triplet-to-arch.sh $HOST) -s -cdrom Spartix.iso -drive file=hdd.img,format=raw,index=0,media=disk -m 1024M -monitor stdio  -boot d -net nic,model=e1000 -net dump,file=net.pcap -net user --enable-kvm
