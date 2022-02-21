PROJECTS:=kernel
SOURCE_PACKAGES:= photon libtest
export ONYX_ARCH:=$(shell scripts/onyx_arch.sh)

include usystem/Makefile

ALL_MODULES:=$(PROJECTS) $(SOURCE_PACKAGES) $(patsubst %, usystem/%, $(USYSTEM_PROJS))

.PHONY: all iso clean build-prep $(SYSTEM_HEADER_PROJECTS) $(PROJECTS) \
$(SOURCE_PACKAGES) build-cleanup musl

export DESTDIR:=$(PWD)/sysroot
export HOST?=$(shell scripts/arch-to-host.sh $(ONYX_ARCH))
export BUILDPKG_BIN?=$(PWD)/buildpkg/buildpkg
export BUILDPKG_BIN_PY_WRAPPER?=$(PWD)/buildpkg/buildpkg_gn_wrapper

ifneq ($(CLANG_PATH),)

export CLANG_ARGUMENTS:=--target=$(ONYX_ARCH)-unknown-onyx
export CLANG_BIN:=$(CLANG_PATH)/bin
export AR:=$(CLANG_BIN)/llvm-ar
export CC:=$(CLANG_BIN)/clang $(CLANG_ARGUMENTS)
export CC_BARE_PATH:=$(CLANG_BIN)/clang
export AS:=$(CC)
export CXX:=$(CLANG_BIN)/clang++ $(CLANG_ARGUMENTS)
export NM:=$(CLANG_BIN)/llvm-nm
export LD:=$(CLANG_BIN)/ld
export STRIP:=$(CLANG_BIN)/llvm-strip
export RANLIB:=$(CLANG_BIN)/llvm-ranlib

export ONYX_USING_CLANG:=yes

else

export AR:=$(HOST)-ar
export AS:=$(HOST)-as
export CC:=$(HOST)-gcc
export CC_BARE_PATH:=$(shell which $(CC))
export CXX:=$(HOST)-g++
export NM:=$(HOST)-nm
export LD:=$(HOST)-ld.bfd
export STRIP:=$(HOST)-strip
export RANLIB:=$(HOST)-ranlib

endif

export PREFIX:=/usr
export EXEC_PREFIX:=$(PREFIX)
export BOOTDIR:=/boot
export LIBDIR:=$(EXEC_PREFIX)/lib
export INCLUDEDIR:=$(PREFIX)/include
export BINDIR:=$(PREFIX)/bin
export MANDIR:=/usr/share/man
export PKGDIR:=/pkg

ifeq ($(ONYX_ARCH), riscv64)
ifeq ($(ONYX_USING_CLANG), yes)
export EXTRA_CFLAGS:=-mno-relax
endif
endif

export CFLAGS?=-O2 -g $(EXTRA_CFLAGS)
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
build-prep:
	mkdir -p sysroot

install-packages: $(PROJECTS)

kernel-config-h:
	$(MAKE) -C kernel/ include/onyx/config.h

kernel: install-headers
	rm -f kernel/clang-tidy.out
	$(MAKE) -C $@ install

musl:
	scripts/check_reconf.sh musl --enable-debug --prefix=/usr --syslibdir=/usr/lib
	$(MAKE) -C musl install-headers
	$(MAKE) -C $@ install

wserver: $(SOURCE_PACKAGES)
	$(MAKE) -C $@ install
 
singularity: musl install-packages wserver
	$(MAKE) -C $@ install

$(SOURCE_PACKAGES): musl install-packages
	$(MAKE) -C $@ install

$(USYSTEM_DFL_RULE_PROJS): musl install-packages
	$(MAKE) -C usystem/$@ install

dash: musl install-packages
	./scripts/check_reconf.sh usystem/dash --prefix=/usr --enable-static
	$(MAKE) -C usystem/$@ install
	ln -sf dash $(DESTDIR)$(BINDIR)/sh

install-headers: build-prep
	$(MAKE) -C kernel install-headers
	$(MAKE) -C photon install-headers

build-srcpackages: $(SOURCE_PACKAGES)

build-gn: musl libtest install-packages
	cd usystem && ninja -C out/ system && ./copy_packages.sh && ./uncompress_packages.sh && cd ..

build-usystem: build-srcpackages $(USYSTEM_PROJS) build-gn

build-cleanup: build-usystem 
	cp kernel/kernel.config sysroot/boot/

	# TODO: Do this in kernel/Makefile
	$(NM) kernel/vmonyx > Kernel.map

fullbuild: build-cleanup

iso: fullbuild
	scripts/iso.sh

fullbuild-plus-initrd: fullbuild
	SYSTEM_ROOT=$(SYSROOT) scripts/geninitrd --compression-method none scripts/default-initrd.sh

qemu-riscv: fullbuild-plus-initrd
	qemu-system-$(shell scripts/target-triplet-to-arch.sh $(HOST)) -kernel kernel/vmonyx -m 512M -machine virt \
	-monitor stdio -s -initrd initrd.tar

qemu-arm64: kernel
	qemu-system-$(shell scripts/target-triplet-to-arch.sh $(HOST)) -kernel kernel/vmonyx -m 512M -machine virt \
	-monitor stdio -cpu cortex-a53

qemu: iso
	qemu-system-$(shell scripts/target-triplet-to-arch.sh $(HOST)) \
	-s -cdrom Onyx.iso -drive file=hdd.img,format=raw,media=disk -m 512M \
	-monitor stdio -boot d -netdev user,id=u1 -device virtio-net,netdev=u1 \
	-object filter-dump,id=f1,netdev=u1,file=net.pcap \
	-enable-kvm -cpu host,migratable=on,+invtsc -smp 4 -vga qxl \
	-device usb-ehci -device usb-mouse \
	-display gtk,gl=on -machine q35

# -device pci-bridge,id=pci_b0,bus=pcie.0,chassis_nr=2,addr=10
# -device ati-vga,bus=pci_b0,addr=1 -device pxb-pcie,id=pcie.1,bus_nr=0x40
#-device ioh3420,id=root_port1,bus=pcie.1 -device ati-vga,bus=root_port1

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



