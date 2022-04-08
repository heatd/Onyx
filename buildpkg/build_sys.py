#!/bin/python3
import os
import argparse
import json
import tempfile
import subprocess

package_tree = ""
onyx_root = ""

def generate_meson_cross(clang_path, onyx_arch):
	global onyx_root
	onyx_triple = onyx_arch + "-onyx"
	cc = onyx_triple + "-gcc"
	cxx = onyx_triple + "-g++"
	strip = onyx_triple + "-strip"
	sysroot = os.path.join(onyx_root, "sysroot")
	pkgconfig = os.path.join(onyx_root, "buildpkg/onyx-pkg-config")
	cflags = f"'--sysroot={sysroot}'"

	if clang_path != None:
		cc = os.path.join(clang_path, "bin/clang")
		cxx = os.path.join(clang_path, "bin/clang++")
		strip = os.path.join(clang_path, "bin/llvm-strip")
		cflags += f", '--target={onyx_arch}-unknown-onyx'"
	
	pkg_config_libdir = os.path.join(sysroot, "usr/lib/pkgconfig")
 
	temp = tempfile.NamedTemporaryFile()
	temp.write(f"""[host_machine]
system = 'onyx'
cpu_family = '{onyx_arch}'
cpu = '{onyx_arch}'
endian = 'little'
[properties]
sys_root = '{sysroot}'
pkg_config_libdir = '{pkg_config_libdir}'
c_args = [{cflags}]
cpp_args = [{cflags}]
c_link_args = [{cflags}]
[binaries]
c = '{cc}'
cpp = '{cxx}'
strip = '{strip}'
pkgconfig = '{pkgconfig}'
""".encode())

	temp.flush()
	return temp


def check_version(package_version, dep_version_string):
	may_be_greater = dep_version_string.startswith(">=")
	dep_ver = dep_version_string.replace(">=", "")
	print(package_version)
	print(dep_ver)

	# TODO: Lexigraphic comparison doesn't work here, because you can go from 9 -> 10 and to the code
	# 10 will be lesser than 9 
	if may_be_greater:
		return package_version >= dep_ver
	return package_version == dep_ver

class Package:

	def is_pkg_group(self):
		return "package-group" in self.data

	def __init__(self, name):
		self.name = name
		self.package_path = os.path.join(package_tree, name)
		with open(os.path.join(self.package_path, "meta.json")) as metafile:
			self.data = json.load(metafile)
		
		if self.is_pkg_group():
			self.deps = self.data["members"]
		else:
			self.deps = self.data["deps"] 

	def get_deps(self):
		return self.deps
	
	def get_version(self):
		return self.data["version"]

	def satisfies_soname(self, soname):
		if "provides" not in self.data:
			return False
		
		provides = self.data["provides"]

		for p in provides:
			if p["soname"].startswith(soname):
				return True
		
		return False
	
	def satisfy_soname(self, packages, soname):
		deps = self.get_deps()
		for dep in deps:
			package = packages[dep["name"]]

			if package.satisfies_soname(soname):
				return True
		
		return False
	
	def check_deps(self, packages):
		deps = self.get_deps()

		for dep in deps:
			name = dep["name"]
			version = dep["version"]
			resolved = packages[name]

			if check_version(resolved.get_version(), version) == False:
				print(f'Error: Package {self.name} has a dependency on {name}, version {version}'
				      f' but it cannot be satisfied as it\'s only version {resolved.get_version()}')
				raise Exception
		
		# Woohoo, we're done here
		if "shared_lib_deps" not in self.data:
			return
		
		shared_lib_deps = self.data["shared_lib_deps"]

		for libdep in shared_lib_deps:
			if not self.satisfy_soname(packages, libdep["name"]):
				print(f'Error: Package {self.name} has a dependency on soname {libdep["name"]}'
				      f' but it cannot be satisfied.')
				raise Exception
	
	def get_build_options(self):
		metabuild_path = os.path.join(self.package_path, "meta_build.json")
		extra_env = {}
		if not os.path.isfile(metabuild_path):
			return extra_env
		
		with open(metabuild_path) as metafile:
			metabuild_options = json.load(metafile)

			if metabuild_options.get("no_force_cc_env") == "true":
				extra_env["ONYX_DONT_FORCE_CC_ENV"] = "true"
		
		return extra_env

	def build(self):
		global onyx_root
		os.environ["ONYX_ROOT"] = onyx_root
		sysroot = os.path.join(onyx_root, "sysroot")
		os.environ["SYSROOT"] = sysroot
		os.environ["ONYX_TARGET"] = os.environ["ONYX_ARCH"] + "-onyx"
		os.environ["ONYX_CONFIGURE_OPTIONS"] = f'--host={os.environ["ONYX_TARGET"]}'
		os.environ["ONYX_CMAKE_OPTIONS"] = f'-DCMAKE_MODULE_PATH={os.path.join(onyx_root, "toolchains/cmake")} -DCMAKE_SYSTEM_NAME=Onyx'
		extra_env = self.get_build_options()
	
		with generate_meson_cross(os.getenv("CLANG_PATH"), os.getenv("ONYX_ARCH")) as meson_cross:

			os.environ["ONYX_MESON_OPTIONS"] = f'--cross-file {meson_cross.name}'

			buildhelper = os.path.join(onyx_root, "buildpkg/build_sys-helper.sh")

			ret = subprocess.run([buildhelper, self.package_path], env={**dict(os.environ), **extra_env})

			if ret.returncode != 0:
				print(f'Error: buildpkg {self.name} exited with status code {ret.returncode} != 0')
				raise Exception

			tarball_name = f'{self.name}-{self.get_version()}.tar.zst'

			ret = subprocess.run(["tar", "xf", tarball_name, "-C", sysroot])
			if ret.returncode != 0:
				print(f'Error: Failed to extract package {self.name} exited with status code {ret.returncode} != 0')
				raise Exception



def ensure_deps_are_resolved(package_list):
	for pkg in package_list.values():
		if pkg.is_pkg_group():
			continue
		pkg.check_deps(package_list)

def resolve_packages(to_build, package_list, skip_deps):
	
	# For each package in to_build, look at its metadata and see what it depends on
	# or what its members are, if it's a package group 
	for pkg_name in to_build:
		pkg = Package(pkg_name)

		package_list[pkg_name] = pkg
		pkg_deps = pkg.get_deps()

		if skip_deps:
			continue

		for dep in pkg_deps:
			if dep["name"] not in to_build:
				to_build.append(dep["name"])

	print(package_list)
	print(to_build)

	if not skip_deps:
		ensure_deps_are_resolved(package_list)

def build_packages(packages, skip_deps):
	
	while len(packages) != 0:
		to_delete = []
		for package in packages.values():
			#print(f'Package {package.name} deps {package.get_deps()}')
			if skip_deps or len(package.get_deps()) == 0:
				print(f'Building {package.name}!')

				if not package.is_pkg_group():
					package.build()
				for pkg in packages.values():
					deps = pkg.get_deps()
					for dep in deps:
						if dep["name"] == package.name:
							deps.remove(dep)
							break
				to_delete.append(package)

		for delete in to_delete:
			packages.pop(delete.name);


def main():
	parser = argparse.ArgumentParser(description = "Build a package and its dependencies inside a tree")
	parser.add_argument("package_tree", help = "Path to the package tree you want to build", type = str)
	parser.add_argument("onyx_root", metavar = "onyx-root", help = "Path to the Onyx root directory", type = str)
	parser.add_argument("packages", metavar = "package", type = str, nargs = "+", help = "Package(s) to build")
	parser.add_argument("--install-all", help = "Installs every package, even if they're not strict dependencies of a package")
	parser.add_argument("--skip-deps", action='store_true', help = "Skip building dependencies")
	args = parser.parse_args()

	to_build = args.packages

	#print(to_build)

	packages = {}

	global package_tree
	package_tree = os.path.abspath(args.package_tree)

	global onyx_root
	onyx_root = os.path.abspath(args.onyx_root)


	resolve_packages(to_build, packages, args.skip_deps)

	build_packages(packages, args.skip_deps)


if __name__ == "__main__":
	main()
