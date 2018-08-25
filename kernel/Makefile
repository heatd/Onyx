HOST?=$(shell ../default-host.sh)
HOSTARCH:=$(shell ../target-triplet-to-arch.sh $(HOST))

CFLAGS?=-O2 -g
CPPFLAGS?=
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
BOOTDIR?=$(EXEC_PREFIX)/boot
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -ffreestanding -fbuiltin -Wall -Wextra -fstack-protector-strong \
-Wno-unused-parameter -Wno-unused-function -Werror -fsanitize=undefined -fno-sanitize=alignment

CPPFLAGS:=$(CPPFLAGS) -D__is_onyx_kernel -D_POSIX_C_SOURCE -D_BSD_SOURCE -Iinclude \
-Iinclude/acpica -isystem ../libc/include -DKERNEL_VERSION='"$(KERNEL_VERSION)"' \
-DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"' -imacros \
include/onyx/config.h

LDFLAGS:=$(LDFLAGS) -fwhole-program -fkeep-inline-functions -flto
LIBS:=$(LIBS) -nostdlib -lk -lgcc
ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config

# TODO: Add -finstrument-functions support
CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS) -D ACPI_LIBRARY -D ACPI_DEBUG_OUTPUT=1
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)
ACPICA_CFLAGS:=$(filter-out -fsanitize=undefined -fsanitize=address -Werror, $(CFLAGS))

OBJS:=\
$(patsubst %.c,%.o,$(wildcard drivers/*/*.c)) \
$(patsubst %.cpp,%.o,$(wildcard drivers/*/*.cpp)) \
$(patsubst %.c,%.o,$(wildcard kernel/*.c)) \
$(patsubst %.c,%.o,$(wildcard crypt/*.c)) \
$(patsubst %.cpp,%.o,$(wildcard kernel/*.cpp)) \
$(patsubst %.c,%.o,$(wildcard kernel/*/*.c)) \
$(patsubst %.cpp,%.o,$(wildcard kernel/*/*.cpp)) \
$(filter-out $(ARCHDIR)/__vdso.o, $(patsubst %.c,%.o,$(wildcard $(ARCHDIR)/*.c))) \
$(patsubst %.c,%.o,$(wildcard $(ARCHDIR)/*/*.c)) \
$(filter-out acpica/components/disassembler/%, $(patsubst %.c,%.o,$(wildcard acpica/components/*/*.c))) \
$(filter-out $(ARCHDIR)/crti.o $(ARCHDIR)/__vdso_asm.S, $(patsubst %.S,%.o,$(wildcard $(ARCHDIR)/*.S)))

CRTI_OBJ:=../sysroot/usr/lib/crti.o
CRTBEGIN_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtbegin.o)
CRTEND_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtend.o)
CRTN_OBJ:=../sysroot/usr/lib/crtn.o

ALL_OUR_OBJS:=\
$(CRTI_OBJ) \
$(OBJS) \
$(CRTN_OBJ) \

OBJ_LINK_LIST:=\
$(CRTI_OBJ) \
$(CRTBEGIN_OBJ) \
$(OBJS) \
$(CRTEND_OBJ) \
$(CRTN_OBJ) \

VDSO_LDFLAGS:= -Wl,-Bsymbolic -shared \
-Wl,-soname=onyx-vdso.so.0 -fpic \
-T $(ARCHDIR)/vdso.ld -z max-page-size=0x1000 \
-z common-page-size=0x1000

all: onyx-vdso.so.0 vmonyx

.PHONY: all clean install install-headers install-kernel kernel-modules

vmonyx: $(OBJ_LINK_LIST) $(ARCHDIR)/linker.ld
	@echo [LD] $@
	@$(CC) -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS)
	cp vmonyx vmonyx-unstripped
	strip -g vmonyx
acpica/%.o: acpica/%.c
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(CPPFLAGS)
%.o: %.c
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(CFLAGS) $(CPPFLAGS) -Wno-error=deprecated-declarations
%.o: %.S
	@echo [AS] $<
	@$(CC) -c $(CPPFLAGS) -o $@ $<
%.o: %.cpp
	@echo [CXX] $<
	@$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)
$(ARCHDIR)/__vdso.o: $(ARCHDIR)/__vdso.c
	@echo [CC] $<
	@$(CC) -c $< -o $@ -fpic -Iinclude/acpica -Iinclude -isystem ../libc/include
onyx-vdso.so.0: $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o
	@echo [VDSO]
	$(CC) $(VDSO_LDFLAGS) $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o -o $@ -ffreestanding \
	 -nostdlib -Iinclude -I../libc/include
clean:
	rm -f vmonyx $(OBJS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o
	$(MAKE) -C modules/ clean

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)
	cp -RTv drivers/include $(DESTDIR)$(INCLUDEDIR)/drivers

install-kernel: vmonyx kernel-modules onyx-vdso.so.0
	mkdir -p $(DESTDIR)$(BOOTDIR)
	# Create livefs directories
	mkdir -p $(DESTDIR)/dev/
	mkdir -p $(DESTDIR)/proc/
	mkdir -p $(DESTDIR)/var/
	mkdir -p $(DESTDIR)/tmp/
	mkdir -p $(DESTDIR)/sys/
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $<  $(DESTDIR)$(BOOTDIR)
	cp onyx-vdso.so.0 $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)/usr/share
	mkdir -p $(DESTDIR)/usr/share/man
	mkdir -p $(DESTDIR)/usr/share/man/man9
	cp onyx.9 $(DESTDIR)/usr/share/man/man9
kernel-modules:
	$(MAKE) -C modules/
