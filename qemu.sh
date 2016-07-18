#!/bin/sh
set -e
. ./iso.sh

/opt/qemu/bin/qemu-system-$(./target-triplet-to-arch.sh $HOST) -cdrom Spartix.iso -m 1024M -monitor stdio -d cpu_reset -boot d -drive file=hdd.img,if=none,id=TEST -device ich9-ahci,id=ahci -device ide-drive,drive=TEST,bus=ahci.0
