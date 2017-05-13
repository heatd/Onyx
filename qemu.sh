#!/bin/sh
set -e
. ./iso.sh
QEMU_PREFIX=${QEMU_PREFIX:-/usr/bin}


$QEMU_PREFIX/qemu-system-$(./target-triplet-to-arch.sh $HOST) -s -cdrom Onyx.iso -drive file=hdd.img,format=raw,media=disk -m 512M -monitor stdio -boot d --enable-kvm -smp 4 -cpu SandyBridge,+avx -d int -vga vmware -device ioh3420 -netdev user,id=net0,dump,file=net.pcap -device e1000,netdev=net0

