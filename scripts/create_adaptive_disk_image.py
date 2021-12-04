#!/bin/python3
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#

import sys
import subprocess

def main():
    if len(sys.argv) < 3:
        print("create_adaptive_disk_image.py: Bad usage")
        exit(1)

    # Our argument is whatever du(1) calculated, in 1024-byte units
    nr_1024_blocks = int(sys.argv[1])

    nr_1024_blocks = nr_1024_blocks * 1024
    # Have the final partition image be 20% larger than the total size
    # Note that it might be a decent idea to have this be adjustable by the user
    # or maybe we get could a better estimate.
    nr_1024_blocks = int(nr_1024_blocks * 1.20)

    return subprocess.run(["fallocate", "-l", str(nr_1024_blocks), sys.argv[2]]).returncode

if __name__ == "__main__":
    main()
    
