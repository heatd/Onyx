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
-Wno-error=invalid-offsetof -fno-sanitize=pointer-overflow -fvisibility=protected \
-Wno-missing-field-initializers -Wno-format-truncation -Wstrict-aliasing

# NOTE: I don't think pointer-overflow works with kernel pointers

CPPFLAGS:=$(CPPFLAGS) -D__is_onyx_kernel -D_POSIX_C_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE -Iinclude \
-Iinclude/acpica -isystem ../libc/include -DKERNEL_VERSION='"$(KERNEL_VERSION)"' \
-DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"' -imacros \
include/onyx/config.h

LDFLAGS:=$(LDFLAGS) -fkeep-inline-functions -no-pie -Wl,--build-id=none
LIBS:=$(LIBS) -nostdlib -lk $(LIBGCC_PATH)
ARCHDIR:=arch/$(HOSTARCH)

include kernel.config
include $(ARCHDIR)/make.config

CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)

# NOT RECOMMENDED, IS BROKEN
ifeq ($(CONFIG_LTO), y)
CFLAGS+=-flto
endif

ifeq ($(CONFIG_KASAN), y)
CFLAGS+=-fsanitize=kernel-address
endif

ifeq ($(CONFIG_KTRACE), y)
# mrecord-mcount breaks templates, and that's bad :/ TODO: One day, figure out if it's fixable
# C_ONLY_CFLAGS+=-pg -mnop-mcount -mfentry -mrecord-mcount -minstrument-return=nop5 -mrecord-return
endif

ifeq ($(CONFIG_UBSAN), y)
CFLAGS+=-fsanitize=undefined -fno-sanitize=alignment -fno-sanitize=pointer-overflow
endif

ifeq ($(CONFIG_RELOCATABLE), y)
CFLAGS+=-fno-plt -fPIE
else
CFLAGS+=-fno-pie
endif

CLANG_TIDY_CHECKS:="performance*, modernize-pass-by-value, readability*, misc*, \
		-readability-implicit-bool-conversion, -readability-braces-around-statements, \
		-readability-else-after-return, -readability-isolate-declaration, \
		-readability-magic-numbers, -misc-unused-parameters, \
		-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling, \
		-readability-inconsistent-declaration-parameter-name, -readability-qualified-auto, \
		-misc-non-private-member-variables-in-classes, -clang-diagnostic-unknown-attributes, \
		cppcoreguidelines-slicing, cppcoreguidelines-pro-type-const-cast, \
		google-runtime-operator, bugprone*, -bugprone-narrowing-conversions, \
		clang-analyzer-optin.performance.Padding, modernize-use-override, \
		-bugprone-reserved-identifier, -misc-no-recursion"

CXXFLAGS:=-fno-rtti -fno-exceptions -fcheck-new
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS) -D ACPI_LIBRARY -D ACPI_DEBUG_OUTPUT=1
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)
ACPICA_CFLAGS:=$(filter-out -fsanitize=undefined -Werror, $(CFLAGS))

# clang-tidy doesn't recognize a bunch of compiler flags
CLANG_TIDY_CFLAGS:=$(filter-out -mnop-mcount -mrecord-mcount -mrecord-return \
	-Wno-error=frame-address -minstrument-return=nop5 \
	-Wno-cast-function-type -Wno-format-truncation, $(CFLAGS))

RUN_CLANG_TIDY?=1

ifeq ($(RUN_CLANG_TIDY), 1)
CLANG_TIDY:=@-clang-tidy --color -checks=$(CLANG_TIDY_CHECKS)
CLANG_TIDY_ARGS:=-- $(CLANG_TIDY_CFLAGS) -std=c++20 $(CXXFLAGS) $(CPPFLAGS) \
--sysroot=$(SYSROOT) -D__onyx__ -U__linux__ -U_LINUX
else
CLANG_TIDY:=true
CLANG_TIDY_ARGS:=
endif


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
CRTBEGIN_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtbeginS.o)
CRTEND_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtendS.o)
LIBGCC_PATH:=$(shell $(CC) $(CFLAGS)  $(LDFLAGS) -print-libgcc-file-name)
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
-z max-page-size=0x1000 -z common-page-size=0x1000 \
-T $(ARCHDIR)/vdso.ld

all: onyx-vdso.so.0 vmonyx

.PHONY: all clean install install-headers install-kernel kernel-modules

vmonyx: $(OBJ_LINK_LIST) $(ARCHDIR)/linker.ld ../libc/libk.a
	@echo [LD] $@
	# Very important to note that right now, the kernel can only link using
	# ld.bfd due to linker script weirdness. Because of that, we pass -fuse-ld=bfd
	$(CC) -fuse-ld=bfd -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS) -lgcc
	cp vmonyx vmonyx-unstripped
	strip -g vmonyx

acpica/%.o: acpica/%.c kernel.config
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) $(CPPFLAGS)

kernel/mm/kasan.o: kernel/mm/kasan.c
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) -fno-sanitize=kernel-address -fno-lto $(CPPFLAGS)

kernel/mm/malloc/%.o: kernel/mm/malloc/%.c kernel.config
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) -fno-sanitize=kernel-address -fno-lto $(CPPFLAGS)

# I don't like this solution of having an ifeq RUN_CLANG_TIDY but I can't find a better way to do this and still pass $<

%.o: %.c kernel.config
	@echo [CC] $<

#ifeq ($(RUN_CLANG_TIDY), 1)
#	$(CLANG_TIDY) $< $(CLANG_TIDY_ARGS)
#endif
	@$(CC) -c $< -o $@ -std=c11 $(CFLAGS) $(CPPFLAGS) $(C_ONLY_CFLAGS) -Wno-error=deprecated-declarations

%.o: %.S kernel.config
	@echo [AS] $<
	@$(CC) -c $(CPPFLAGS) -o $@ $<

%.o: %.cpp kernel.config
	@echo [CXX] $<
	@$(CXX) -c $< -o $@ -std=c++20 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)

ifeq ($(RUN_CLANG_TIDY), 1)
	$(CLANG_TIDY) $< $(CLANG_TIDY_ARGS)
endif

$(ARCHDIR)/__vdso.o: $(ARCHDIR)/__vdso.c kernel.config
	@echo [CC] $<
	@$(CC) -c $< -o $@ -fpic -Iinclude/acpica -Iinclude -isystem ../libc/include -fno-zero-initialized-in-bss

onyx-vdso.so.0: $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o kernel.config
	@echo [VDSO]
	$(CC) $(VDSO_LDFLAGS) $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o -o $@ -ffreestanding \
	 -nostdlib -Iinclude -I../libc/include -Wl,--hash-style=both -fuse-ld=bfd

clean: clean-modules
	rm -f vmonyx $(OBJS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o
	rm -f clang-tidy.out

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
