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

include ../kversion.config
CFLAGS:=$(CFLAGS) -ffreestanding -fbuiltin -Wall -Wextra -Wno-format -fstack-protector-strong -Wno-unused-parameter -Wno-unused-function -Werror
CPPFLAGS:=$(CPPFLAGS) -D__is_onyx_kernel -D_POSIX_C_SOURCE -D_BSD_SOURCE -Iinclude -Iinclude/acpica -DKERNEL_VERSION='"$(KERNEL_VERSION)"' -DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"'
LDFLAGS:=$(LDFLAGS) -fwhole-program -fkeep-inline-functions -flto
LIBS:=$(LIBS) -nostdlib -lk -lgcc
ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config
CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS) -D ACPI_LIBRARY -D ACPI_DEBUG_OUTPUT=1
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS) $(BUILD_NUMBER_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)
ACPICA_CFLAGS:=$(filter-out -fsanitize=undefined -fsanitize=address -Werror, $(CFLAGS))

OBJS:=\
$(patsubst %.c,%.o,$(wildcard drivers/*/*.c)) \
$(patsubst %.c,%.o,$(wildcard kernel/*.c)) \
$(patsubst %.c,%.o,$(wildcard kernel/*/*.c)) \
$(patsubst %.c,%.o,$(wildcard $(ARCHDIR)/*.c)) \
$(filter-out acpica/components/disassembler/%, $(patsubst %.c,%.o,$(wildcard acpica/components/*/*.c))) \
$(filter-out $(ARCHDIR)/crti.o, $(patsubst %.S,%.o,$(wildcard $(ARCHDIR)/*.S)))

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

all: vmonyx

.PHONY: all clean install install-headers install-kernel kernel-modules

vmonyx: BUILD $(OBJ_LINK_LIST) $(ARCHDIR)/linker.ld
	@echo [LD] $@
	@$(CC) -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS)
acpica/%.o: acpica/%.c
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(CPPFLAGS)
%.o: %.c
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(CFLAGS) $(CPPFLAGS) -Wno-error=deprecated-declarations
%.o: %.S
	@echo [AS] $<
	@nasm -felf$(NASMARCH) $< -o $@

%.o: %.cpp
	@echo [CXX] $<
	@$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)

clean:
	rm -f vmonyx $(OBJS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o
	$(MAKE) -C modules/ clean

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)
	cp -RTv drivers/include $(DESTDIR)$(INCLUDEDIR)/drivers

install-kernel: vmonyx kernel-modules
	mkdir -p $(DESTDIR)$(BOOTDIR)
	# Create livefs directories
	mkdir -p $(DESTDIR)/dev/
	mkdir -p $(DESTDIR)/proc/
	mkdir -p $(DESTDIR)/var/
	mkdir -p $(DESTDIR)/tmp/
	mkdir -p $(DESTDIR)/sys/
	cp $<  $(DESTDIR)$(BOOTDIR)

kernel-modules:
	$(MAKE) -C modules/
