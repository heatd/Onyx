#!/bin/sh
PKG_PREFIX="/mnt/onyx-root"
print_usage() {
	echo "pck - Onyx package manager"
	echo "Syntax - pck [command] [package name]"
}
do_help() {
	print_usage
	# NOTE: 16 spaces between columns
	echo "Commands: install                Installs a package"
	echo "          help:                  Shows this help message"
}
COMMAND=$1
PACKAGE=$2

if [ -z "$COMMAND" ]
	then
	    print_usage
	    exit 1
fi

if [ "$COMMAND" = "help" ]; then 
	do_help
	exit 0
fi
if [ "$COMMAND" = "install" ]; then
	rm $PACKAGE.tar.xz
	wget --verbose http://github.com/heatd/onyx-packages/raw/master/$PACKAGE.tar.xz
	tar xf $PACKAGE.tar.xz
	cd $PACKAGE
	source ./pkginstall
	pre_install
	install
	post_install
	cd ..
	# Clean up
	rm -r $PACKAGE
	rm $PACKAGE.tar.xz
	exit 0
fi
if [ "$COMMAND" = "get-source" ]; then
	rm $PACKAGE-src.tar.xz
	wget --verbose http://github.com/heatd/onyx-packages/raw/master/$PACKAGE-src.tar.xz
	echo "Source installed at $(pwd)/$PACKAGE-src.tar.xz"
	exit 0
fi
if [ "$COMMAND" = "build" ]; then
	cd $PACKAGE
	./makepkg
fi