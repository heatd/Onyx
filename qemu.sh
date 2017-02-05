#!/bin/sh
set -e
. ./iso.sh

qemu-system-$(./target-triplet-to-arch.sh $HOST) -s -cdrom Spartix.iso -drive file=hdd.img,if=none,id=ahci.disk,format=raw -device ich9-ahci,id=ahci -device ide-drive,drive=ahci.disk,bus=ahci.0 -m 100M -monitor stdio  -boot d -net nic,model=e1000 -net dump,file=net.pcap -net user --enable-kvm -smp 4 --no-shutdown --no-reboot -cpu SandyBridge,+avx
