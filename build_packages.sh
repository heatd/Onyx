PACKAGES=""

if [ -d ports ]; then
echo "Building packages"
cd ports
for PACKAGE in $PACKAGES; do
	echo "Building $PACKAGE"
	DESTDIR="$PWD/../sysroot" $MAKE -C $PACKAGE install -s
done
cd ..
fi
