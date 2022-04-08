#!/bin/python3

import json
import os
import argparse
from os.path import dirname
import shutil

def ensure_exists(path):
	if not os.path.exists(path):
		os.makedirs(path)

def main():
	parser = argparse.ArgumentParser(description = "Copy files to the system image's sysroot")
	parser.add_argument("--manifest", help = "Path to the manifest", type = str)
	parser.add_argument("-o", help = "Path to the destination sysroot", type = str)
	args = parser.parse_args()

	global manifest_path
	manifest_path = os.path.abspath(args.manifest)

	global destdir
	destdir = os.path.abspath(args.o)

	# TODO: This is a bit hacky no?
	os.chdir(dirname(dirname(manifest_path)))

	ensure_exists(destdir)

	with open(manifest_path) as manifest_file:
		manifest = json.load(manifest_file)

	for f in manifest:
		src = f["source"]
		dest = f["destination"]

		destfile = os.path.join(destdir, dest)

		directory = dirname(destfile)

		# Skip the copying if dest is newer or of the same age as src
		if os.path.exists(dest):
			if os.lstat(dest).st_mtime >= os.lstat(src).st_mtime:
				continue

		ensure_exists(directory)
		
		if os.path.islink(src):
			dst = os.readlink(src)
			if os.path.lexists(destfile):
				os.unlink(destfile)
			os.symlink(dst, destfile)
			continue

		shutil.copyfile(src, destfile)
		shutil.copystat(src, destfile)
		print(dest)
if __name__ == "__main__":
	main()

