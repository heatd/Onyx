#!/usr/bin/env python3

import sys

with open("kernel.config") as file:

	with open(sys.argv[1], "w") as header:
		line_nr = 0
		# TODO: Print copyright header?
		header.write("#ifndef _ONYX_CONFIG_H\n#define _ONYX_CONFIG_H\n\n")
		for line in file:
			line_nr += 1
			line = line.replace('=', ' ')
			tokens = line.split()
			if len(tokens) == 1:
				print("Error: Bad config line at line "
					+ str(line_nr) + "\n")
				exit(1)

			if tokens[1] != "n":
				header.write('#define ' + line)

		header.write("\n#endif\n")