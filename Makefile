PROJECTS:=libc kernel
SOURCE_PACKAGES:= libdrm libunwind init games ld dhcpcd wserver strace

ALL_MODULES:=$(PROJECTS) $(SOURCE_PACKAGES)

.PHONY: all iso clean build-prep geninitrd $(SYSTEM_HEADER_PROJECTS) $(PROJECTS) \
$(SOURCE_PACKAGES) build-cleanup dash

export DESTDIR:=$(PWD)/sysroot
export HOST?=$(shell ./default-host.sh)

export AR:=$(HOST)-ar
export AS:=$(HOST)-as
export CC:=$(HOST)-gcc
export CXX:=$(HOST)-g++
export NM:=$(HOST)-nm
export HOST_CC:=gcc
export PREFIX:=/usr
export EXEC_PREFIX:=$(PREFIX)
export BOOTDIR:=/boot
export LIBDIR:=$(EXEC_PREFIX)/lib
export INCLUDEDIR:=$(PREFIX)/include
export BINDIR:=$(PREFIX)/bin
export MANDIR:=/usr/share/man
export PKGDIR:=/pkg
export CFLAGS?=-Os -g
export CPPFLAGS:=

# Configure the cross-compiler to use the desired system root.
export CXX:=$(CXX) --sysroot=$(PWD)/sysroot
export CC:=$(CC) --sysroot=$(PWD)/sysroot

all: iso

clean:
	for module in $(ALL_MODULES); do $(MAKE) -C $$module clean; done
	./utils/make_utils.sh clean
build-prep:
	mkdir -p sysroot
	cd kernel && ../scripts/config_to_header.py include/onyx/config.h

install-packages: $(PROJECTS)

libc: install-headers
	$(MAKE) -C $@ install

kernel: libc install-headers
	$(MAKE) -C $@ install

musl: install-packages
	$(MAKE) -C $@ install

test: libtest musl install-packages
	$(MAKE) -C $@ install

$(SOURCE_PACKAGES): musl install-packages
	$(MAKE) -C $@ install

install-headers: build-prep
	$(MAKE) -C kernel install-headers
	$(MAKE) -C libdrm install-headers

build-srcpackages: $(SOURCE_PACKAGES)

dash: build-srcpackages
	cd dash && ./configure --prefix=/ --bindir=/usr/bin \
	--host=x86_64-onyx --enable-static && $(MAKE) install && \
	$(MAKE) distclean clean 

build-cleanup: dash 
	cp kernel/kernel.config sysroot/boot
	rm kernel/include/onyx/config.h

	# TODO: Do this in kernel/Makefile
	$(NM) kernel/vmonyx > Kernel.map

fullbuild: build-cleanup
	./utils/make_utils.sh install

iso: fullbuild
	./iso.sh

qemu: iso
	qemu-system-$(shell ./target-triplet-to-arch.sh $(HOST)) \
	-s -cdrom Onyx.iso -drive file=hdd.img,format=raw,media=disk -m 512M \
	-monitor stdio -boot d -net nic,model=e1000 -net dump,file=net.pcap -net user \
	--enable-kvm -smp 2 -cpu IvyBridge,+avx -d int -vga vmware -no-reboot -no-shutdown
