HOST?=$(shell ../default-host.sh)
HOSTARCH:=$(shell ../target-triplet-to-arch.sh $(HOST))

CFLAGS?=-Os -g
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
-Wno-unused-parameter -Wno-unused-function \
-Werror -Wno-error=frame-address -Wno-address-of-packed-member -Wno-cast-function-type \
-fno-sanitize=pointer-overflow -fno-pie

# NOTE: I don't think pointer-overflow works with kernel pointers

CPPFLAGS:=$(CPPFLAGS) -D__is_onyx_kernel -D_POSIX_C_SOURCE -D_BSD_SOURCE -Iinclude \
-Iinclude/acpica -isystem ../libc/include -DKERNEL_VERSION='"$(KERNEL_VERSION)"' \
-DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"' -imacros \
include/onyx/config.h -Wno-missing-field-initializers

LDFLAGS:=$(LDFLAGS) -fkeep-inline-functions -no-pie -Wl,--build-id=none
LIBS:=$(LIBS) -nostdlib -lk $(LIBGCC_PATH)
ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config
include kernel.config

CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)

ifeq ($(CONFIG_KASAN), y)
CFLAGS+=-fsanitize=kernel-address
endif

ifeq ($(CONFIG_KTRACE), y)
CFLAGS+=-pg -mnop-mcount -mfentry -mrecord-mcount -minstrument-return=nop5 -mrecord-return
endif

ifeq ($(CONFIG_UBSAN), y)
CFLAGS+=-fsanitize=undefined -fno-sanitize=alignment -fno-sanitize=pointer-overflow
endif

CXXFLAGS:=-fno-rtti -fno-exceptions -fcheck-new
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS) -D ACPI_LIBRARY -D ACPI_DEBUG_OUTPUT=1
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)
ACPICA_CFLAGS:=$(filter-out -fsanitize=undefined -Werror, $(CFLAGS))

#OBJS:=\
#$(patsubst %.c,%.o,$(wildcard drivers/*/*.c)) \
#$(patsubst %.cpp,%.o,$(wildcard drivers/*/*.cpp)) \
#$(patsubst %.c,%.o,$(wildcard kernel/*.c)) \
#$(patsubst %.c,%.o,$(wildcard crypt/*.c)) \
#$(patsubst %.cpp,%.o,$(wildcard kernel/*.cpp)) \
#$(patsubst %.c,%.o,$(wildcard kernel/*/*.c)) \
#$(patsubst %.c,%.o,$(wildcard kernel/*/*/*.c)) \
#$(patsubst %.cpp,%.o,$(wildcard kernel/*/*.cpp)) \
#$filter-out $(ARCHDIR)/__vdso.o, $(patsubst %.c,%.o,$(wildcard $(ARCHDIR)/*.c))) \
#$(patsubst %.c,%.o,$(wildcard $(ARCHDIR)/*/*.c)) \
#$(patsubst %.cpp,%.o,$(wildcard $(ARCHDIR)/*.cpp)) \
#$(patsubst %.cpp,%.o,$(wildcard $(ARCHDIR)/*/*.cpp)) \
#$(filter-out acpica/components/disassembler/%, $(patsubst %.c,%.o,$(wildcard acpica/components/*/*.c))) \
#$(filter-out $(ARCHDIR)/crti.o $(ARCHDIR)/__vdso_asm.S, $(patsubst %.S,%.o,$(wildcard $(ARCHDIR)/*.S)))

include kernel/Makefile
include $(ARCHDIR)/Makefile
include crypt/Makefile
include drivers/Makefile
include acpica/Makefile

OBJS:=$(obj-y)

CRTI_OBJ:=../sysroot/usr/lib/crti.o
CRTBEGIN_OBJ:=$(shell $(CC) $(CFLAGS) -mcmodel=large $(LDFLAGS) -print-file-name=crtbegin.o)
CRTEND_OBJ:=$(shell $(CC) $(CFLAGS) -mcmodel=large $(LDFLAGS) -print-file-name=crtend.o)
LIBGCC_PATH:=$(shell $(CC) $(CFLAGS) -mcmodel=large $(LDFLAGS) -print-libgcc-file-name)
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

vmonyx: $(OBJ_LINK_LIST) $(ARCHDIR)/linker.ld ../libc/libk.a
	@echo [LD] $@
	# Very important to note that right now, the kernel can only link using
	# ld.bfd due to linker script weirdness. Because of that, we pass -fuse-ld=bfd
	$(CC) -fuse-ld=bfd -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS)
	cp vmonyx vmonyx-unstripped
	strip -g vmonyx

acpica/%.o: acpica/%.c kernel.config
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(CPPFLAGS)

kernel/mm/kasan.o: kernel/mm/kasan.c
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) -fno-sanitize=kernel-address $(CPPFLAGS)

kernel/mm/malloc/%.o: kernel/mm/malloc/%.c
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) -fno-sanitize=kernel-address $(CPPFLAGS)

%.o: %.c kernel.config
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(CFLAGS) $(CPPFLAGS) -Wno-error=deprecated-declarations

%.o: %.S kernel.config
	@echo [AS] $<
	@$(CC) -c $(CPPFLAGS) -o $@ $<

%.o: %.cpp kernel.config
	@echo [CXX] $<
	@$(CXX) -c $< -o $@ -std=c++17 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)

$(ARCHDIR)/__vdso.o: $(ARCHDIR)/__vdso.c kernel.config
	@echo [CC] $<
	@$(CC) -c $< -o $@ -fpic -Iinclude/acpica -Iinclude -isystem ../libc/include

onyx-vdso.so.0: $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o kernel.config
	@echo [VDSO]
	$(CC) $(VDSO_LDFLAGS) $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o -o $@ -ffreestanding \
	 -nostdlib -Iinclude -I../libc/include

clean: clean-modules
	rm -f vmonyx $(OBJS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)
	cp -RTv drivers/include $(DESTDIR)$(INCLUDEDIR)/drivers


CPPFLAGS_MODULES:= $(CPPFLAGS) -D __KERNEL_MODULE__

define NEWLINE


endef


$(obj-m): CPPFLAGS:= $(CPPFLAGS_MODULES)

define define_module_target
$(1): $(2)
	$(LD) -r $(2) -o drivers/$(1)/$(1).ko

$(1)-clean:
	rm -f $(2) drivers/$(1)/$(1).ko
endef

$(foreach module, $(modules), $(eval $(call define_module_target,$(module),$$($(module)-y)) $(NEWLINE)))

kernel-modules: $(foreach module, $(modules), $(module))

clean-modules: $(foreach module, $(modules), $(module)-clean)

MODULE_FILES:=$(foreach module, $(modules), drivers/$(module)/$(module).ko)

install-kernel: vmonyx kernel-modules onyx-vdso.so.0
	mkdir -p $(DESTDIR)$(BOOTDIR)
	# Create livefs directories
	mkdir -p $(DESTDIR)/dev/
	mkdir -p $(DESTDIR)/proc/
	mkdir -p $(DESTDIR)/var/
	mkdir -p $(DESTDIR)/tmp/
	mkdir -p $(DESTDIR)/sys/
	mkdir -p $(DESTDIR)/usr/lib/modules
ifneq ($(MODULE_FILES),)
	cp $(MODULE_FILES) $(DESTDIR)/usr/lib/modules
endif
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $<  $(DESTDIR)$(BOOTDIR)
	cp onyx-vdso.so.0 $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)/usr/share
	mkdir -p $(DESTDIR)/usr/share/man
	mkdir -p $(DESTDIR)/usr/share/man/man9
	cp onyx.9 $(DESTDIR)/usr/share/man/man9
