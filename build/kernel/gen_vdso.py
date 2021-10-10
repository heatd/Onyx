#!/bin/python3

import argparse

def main():
    parser = argparse.ArgumentParser(description = "Generate vdso helper, given a path to the vdso shared object")
    parser.add_argument("vdso_path", help = "Path to the vdso you want to include", type = str)
    parser.add_argument("-o", dest = "output_file", help = "Output file", type = str)

    args = parser.parse_args()

    with open(args.output_file, "w") as file:
        file.write(".section .vdso, \"aw\"\n" +
                   ".global __vdso_start\n.global __vdso_end\n" +
                   ".balign 0x1000\n" +
                   "__vdso_start:	.incbin \"" + args.vdso_path + "\"\n" +
                   ".balign 0x1000\n__vdso_end:\n")

if __name__ == "__main__":
    main()
