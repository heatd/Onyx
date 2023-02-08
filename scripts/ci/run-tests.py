#!/bin/python3
# Copyright (c) 2023 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#
import subprocess
import os
import time
import sys
import signal

def ispanic(line: str):
    return line.startswith('panic: ')

def panic(p: subprocess.Popen):
    # Sleep for a bit to get all the output out
    time.sleep(1)
    # Set non blocking and tee everything out
    os.set_blocking(p.stdout.fileno(), False)

    while True:
        line = p.stdout.readline().decode('utf-8')
        if len(line) == 0:
            break
        print(line, end='')
    
    p.kill()

    exit(1)

def calc_execs():
    execs = {}
    use_kvm = True

    var = os.environ.get('USE_KVM', '1')

    if var == '0':
        use_kvm = False

    execs['x86_64'] = ['qemu-system-x86_64', '-s', '-cdrom', 'Onyx.iso', '-m', '1G', '-boot', 'd', '-netdev', 'user,id=u1',
	'-device', 'virtio-net,netdev=u1', '-object', 'filter-dump,id=f1,netdev=u1,file=net.pcap',
	'-cpu', 'Haswell', '-smp', '4', '-device', 'usb-ehci', '-device', 'usb-mouse',
	'-machine', 'q35', '-nographic', '--no-shutdown', '--no-reboot']

    if use_kvm:
        execs['x86_64'] += ['--enable-kvm']
    execs['riscv64'] = ['qemu-system-riscv64', '-kernel', 'kernel/vmonyx', '-m', '512M', '-machine',
                        'virt', '-s', '-initrd', 'initrd.tar', '-smp', '4', '-nographic']
    return execs

def main():
    # Set timeout to 15 minutes
    signal.alarm(15 * 60)
    arch = os.environ.get('ONYX_ARCH', 'x86_64')
    execs = calc_execs()

    if execs.get(arch) == None:
        print(f'Architecture {arch} is not supported by CI/run-tests.py, returning success. This does not mean it works!')
        exit(0)

    p = subprocess.Popen(execs[arch], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    while True:
        line = p.stdout.readline().decode('utf-8')

        if ispanic(line):
            panic(p)

        print(line, end='')
        # Detect the welcome banner and break 
        if line.startswith('Welcome to Onyx'):
            break

    # Ugh, hate this.
    time.sleep(10)
    # Run the test-runner
    p.stdin.write('test-runner --runs 1\n'.encode('utf-8'))
    p.stdin.flush()
    
    time.sleep(5)
    # Grab the status
    p.stdin.write('echo END-MARKER $?\n'.encode('utf-8'))

    p.stdin.flush()

    last_line = None
    while True:
        last_line = p.stdout.readline().decode('utf-8')
        print(last_line, end='')

        if ispanic(last_line):
            panic(p)

        end_marker_index = last_line.find('END-MARKER')
        if end_marker_index != -1 and not last_line.startswith('echo '):
            last_line = last_line[end_marker_index:]
            break

    print(last_line)

    status = int(last_line.split()[1])

    print(f'run-tests: tests exited with exit status {status}')

    p.kill()

    if status == 0:
        exit(0)
    else:
        exit(1)


if __name__ == "__main__":
    main()
