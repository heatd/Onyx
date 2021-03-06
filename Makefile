PROJECTS:=libc kernel
SOURCE_PACKAGES:= photon libunwind libuuid libtest

include usystem/Makefile

ALL_MODULES:=$(PROJECTS) $(SOURCE_PACKAGES) $(patsubst %, usystem/%, $(USYSTEM_PROJS))

.PHONY: all iso clean build-prep $(SYSTEM_HEADER_PROJECTS) $(PROJECTS) \
$(SOURCE_PACKAGES) build-cleanup musl

export DESTDIR:=$(PWD)/sysroot
export HOST?=$(shell ./default-host.sh)
export BUILDPKG_BIN?=$(PWD)/buildpkg/buildpkg
export BUILDPKG_BIN_PY_WRAPPER?=$(PWD)/buildpkg/buildpkg_gn_wrapper

export AR:=$(HOST)-ar
export AS:=$(HOST)-as
export CC:=$(HOST)-gcc
export CXX:=$(HOST)-g++
export NM:=$(HOST)-nm
export LD:=$(HOST)-ld.bfd
export HOST_CC:=gcc
export PREFIX:=/usr
export EXEC_PREFIX:=$(PREFIX)
export BOOTDIR:=/boot
export LIBDIR:=$(EXEC_PREFIX)/lib
export INCLUDEDIR:=$(PREFIX)/include
export BINDIR:=$(PREFIX)/bin
export MANDIR:=/usr/share/man
export PKGDIR:=/pkg
export CFLAGS?=-O2 -g
export CPPFLAGS:=

export SYSROOT=$(PWD)/sysroot

# Configure the cross-compiler to use the desired system root.
export CXX:=$(CXX) --sysroot=$(PWD)/sysroot
export CC:=$(CC) --sysroot=$(PWD)/sysroot

all: iso

clean:
	for module in $(ALL_MODULES); do $(MAKE) -C $$module clean; done
	cd usystem && gn clean out/ && cd ..
	rm -rf sysroot
	rm -rf initrd.tar.*
	$(MAKE) -C musl clean
	$(MAKE) -C libssp clean
build-prep:
	mkdir -p sysroot
	cd kernel && ../scripts/config_to_header.py include/onyx/config.h

install-packages: $(PROJECTS)

libc: install-headers
	$(MAKE) -C $@ install

kernel: libc install-headers
	rm -f kernel/clang-tidy.out
	$(MAKE) -C $@ install

musl: install-packages
	$(MAKE) -C $@ install

libssp: install-packages musl
	$(MAKE) -C $@ install

singularity: musl libssp install-packages wserver
	$(MAKE) -C $@ install

$(SOURCE_PACKAGES): musl libssp install-packages
	$(MAKE) -C $@ install

$(USYSTEM_DFL_RULE_PROJS): musl libssp install-packages
	$(MAKE) -C usystem/$@ install

dash: musl libssp install-packages
	test -f usystem/dash/Makefile || sh -c "cd usystem/dash && \
	     ./configure --prefix=/ --bindir=/usr/bin --host=x86_64-onyx --enable-static 2> /dev/null \
		 && cd ../.."
	$(MAKE) -C usystem/$@ install
	ln -sf dash $(DESTDIR)$(BINDIR)/sh

install-headers: build-prep
	$(MAKE) -C kernel install-headers
	$(MAKE) -C musl install-headers
	$(MAKE) -C photon install-headers

build-srcpackages: $(SOURCE_PACKAGES)

build-gn: musl libssp libtest install-packages
	cd usystem && ninja -C out/ system && ./copy_packages.sh && ./uncompress_packages.sh && cd ..

build-usystem: build-srcpackages $(USYSTEM_PROJS) build-gn

build-cleanup: build-usystem 
	cp kernel/kernel.config sysroot/boot/
	rm -f kernel/include/onyx/config.h

	# TODO: Do this in kernel/Makefile
	$(NM) kernel/vmonyx > Kernel.map

fullbuild: build-cleanup

iso: fullbuild
	./iso.sh

qemu: iso
	qemu-system-$(shell ./target-triplet-to-arch.sh $(HOST)) \
	-s -cdrom Onyx.iso -drive file=hdd.img,format=raw,media=disk -m 512M \
	-monitor stdio -boot d -netdev user,id=u1 -device e1000,netdev=u1 \
	-object filter-dump,id=f1,netdev=u1,file=net.pcap \
	-enable-kvm -cpu host,migratable=on,+invtsc -smp 4 -vga qxl \
	-device usb-ehci -device usb-mouse \
	-display gtk,gl=on -machine q35

intel-passthrough-qemu: iso
	sudo qemu-system-x86_64 -vga none -display gtk,gl=on \
	-device vfio-pci,sysfsdev=/sys/devices/pci0000\:00/0000\:00\:02.0/d507ce65-255a-4b85-88b5-0090410c0b5c,display=on,x-igd-opregion=on,\
	ramfb=on,driver=vfio-pci-nohotplug \
	-enable-kvm -s -cdrom Onyx.iso \
	-machine q35 -drive file=hdd.img,format=raw,media=disk -m 512M \
	-boot d -netdev user,id=u1 -device virtio-net,netdev=u1 \
	-object filter-dump,id=f1,netdev=u1,file=net.pcap \
	-smp 2 -cpu host,migratable=on,+invtsc

virtualbox: iso
	virtualbox --startvm Onyx --dbg



