#!/bin/python3
#
# Copyright (c) 2021 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#
# SPDX-License-Identifier: MIT
#

import argparse
import subprocess
import os

def main():
    parser = argparse.ArgumentParser(description = "Configure and make a package")
    parser.add_argument("package", help = "Path to the package you want to build", type = str)
    parser.add_argument("staging_dir", metavar = "staging-dir", help = "Path to the staging directory", type = str)
    parser.add_argument("sysroot", help = "Path to the Onyx sysroot", type = str)
    parser.add_argument("configure_args", metavar = "configure-args", help = "Configure arguments", type = str)
    parser.add_argument("make_target", metavar = "make-target", help = "Target to be built by make", type = str)
    args = parser.parse_args()

    os.chdir(args.staging_dir)

    package_path = args.package
    subprocess.run(package_path + "/configure " + args.configure_args, shell = True, check = True)

    subprocess.run(["make", "-j4", args.make_target], check = True)

    os.environ["DESTDIR"] = args.sysroot

    subprocess.run(["make", "-j4", "install"], check = True)

main()
