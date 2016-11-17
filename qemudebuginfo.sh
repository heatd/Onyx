#!/bin/bash
export HOST=${HOST:-$(./default-host.sh)}
echo "Starting debugging session"
qemu-system-$(./target-triplet-to-arch.sh $HOST) -cdrom Spartix.iso -d int -m 1024M -boot d -s -drive file=hdd.img,format=raw,index=0,media=disk -net nic,model=e1000 -net dump,file=net.pcap -net user -smp 4
echo "Output written to qemudbg.log"
