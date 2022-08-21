HOSTARCH:=$(ONYX_ARCH)

include kernel.config

ifeq ($(CONFIG_CC_OPTIMIZE_SIZE), y)
CFLAGS?=-Os -g
else
CFLAGS?=-O2 -g
endif

CPPFLAGS?=
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
BOOTDIR?=$(EXEC_PREFIX)/boot
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -MMD -ffreestanding -fbuiltin -Wall -Wextra -fstack-protector-strong \
-Wno-unused-parameter -Wno-unused-function \
-Werror -Wno-error=frame-address -Wno-address-of-packed-member \
-Wno-error=invalid-offsetof -fno-sanitize=pointer-overflow -fvisibility=protected \
-Wno-missing-field-initializers -Wstrict-aliasing -fno-unwind-tables -fno-asynchronous-unwind-tables

ifneq ($(ONYX_USING_CLANG), yes)
# TODO: Find suitable alternatives for clang
CFLAGS:=$(CFLAGS) -Wno-format-truncation -Wshadow-compatible-local

# Note: We need to define _GLIBCXX_INCLUDE_NEXT_C_HEADERS so the shenanigans in the
# compiler (in this case, only GCC)'s stdlib.h C++ wrappers get bypassed. If we let stdlib.h include cstdlib,
# like it wants to when (__cplusplus || _GLIBCXX_INCLUDE_NEXT_C_HEADERS) is false, it inlines a bunch of
# functions with __builtin_*(), which in many cases have double and float arguments and GCC breaks due to
# floating point being disabled

CPPFLAGS:=$(CPPFLAGS) -D_GLIBCXX_INCLUDE_NEXT_C_HEADERS
else

# Explanation for these options:
# -Wno-null-pointer-arithmetic: ACPICA triggers this with ACPI_ROOT_OBJECT
# -Wno-unknown-attributes: as of llvm 11.0.0, it doesn't recognize [[likely]] and [[unlikely]], which we do
#     use quite often.
# -Wno-missing-braces: Seems broken? At least it started spitting out weird ones for IPv6 code(IN6ADDR_ALL_NODES)
#	  in onyx/net/ipv6.h
CFLAGS:=$(CFLAGS) -Wno-null-pointer-arithmetic -Wno-unknown-attributes -Wno-error=unused-private-field \
	-Wno-missing-braces -Wno-c99-designator
endif

# NOTE: I don't think pointer-overflow works with kernel pointers

CPPFLAGS:=$(CPPFLAGS) --sysroot=lib/libk -D__is_onyx_kernel -D_POSIX_C_SOURCE \
-D_BSD_SOURCE -D_GNU_SOURCE -Iinclude \
-DKERNEL_VERSION='"$(KERNEL_VERSION)"' \
-DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"' -imacros \
include/onyx/config.h

LDFLAGS:=$(LDFLAGS) -fkeep-inline-functions -Wl,--build-id=none

include lib/compiler-rt/builtins/Makefile

LIBS:=$(LIBS) -nostdlib
ARCHDIR:=arch/$(HOSTARCH)

GENERATED_HEADERS:=include/onyx/config.h include/onyx/gen/syscall.h

include/onyx/config.h: ../scripts/config_to_header.py kernel.config
	../scripts/config_to_header.py include/onyx/config.h

include $(ARCHDIR)/make.config


ifeq ($(CONFIG_RISCV), y)

include lib/libfdt/Makefile
include lib/device_tree/Makefile

endif

ifeq ($(CONFIG_ARM64), y)

include lib/libfdt/Makefile
include lib/device_tree/Makefile

KERNEL_REQUIRES_FLATTENING:=yes

endif

include lib/libk/Makefile

LIBK_LINK:=lib/libk/libk.a

CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)

ifeq ($(CONFIG_LTO), y)
CFLAGS+=-flto

ifneq ($(ONYX_USING_CLANG), yes)
# GCC behaves weirdly when linking fat and non-fat lto object files together
CFLAGS+=-ffat-lto-objects
LIBK_LINK:=$(libk-objs)
endif

endif

ifeq ($(CONFIG_KASAN), y)
CFLAGS+=-fsanitize=address

ifeq ($(ONYX_USING_CLANG), yes)

# Note: clang tries really hard to access the linear map, but we don't have a linear map (just yet!)
# Therefore, we disable it for now
CFLAGS+=-mllvm -asan-instrumentation-with-call-threshold=0 -mllvm -asan-globals-live-support=false
CFLAGS+=-mllvm -asan-stack=0 -mllvm -asan-globals=0
else
CFLAGS+=--param asan-globals=0 --param asan-instrumentation-with-call-threshold=0 --param asan-stack=0 --param asan-globals=0
endif

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


# TODO: Fix -Wno-mismatched-new-delete cases
CXXFLAGS:=-fno-rtti -fno-exceptions -fcheck-new -Wno-mismatched-new-delete

CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS) -D ACPI_LIBRARY -Wno-error=deprecated-declarations
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)
ACPICA_CFLAGS:=$(filter-out -fsanitize=undefined -Werror, $(CFLAGS))

# clang-tidy doesn't recognize a bunch of compiler flags
CLANG_TIDY_CFLAGS:=$(filter-out -mnop-mcount -mrecord-mcount -mrecord-return \
	-Wno-error=frame-address -minstrument-return=nop5 \
	-Wno-cast-function-type -Wno-format-truncation -Wshadow-compatible-local, $(CFLAGS))

RUN_CLANG_TIDY?=0

ifeq ($(RUN_CLANG_TIDY), 1)
CLANG_TIDY:=@-clang-tidy --color -checks=$(CLANG_TIDY_CHECKS)
CLANG_TIDY_ARGS:=-- $(CLANG_TIDY_CFLAGS) -std=c++20 $(CXXFLAGS) $(CPPFLAGS) \
--sysroot=$(SYSROOT) -D__onyx__ -U__linux__ -U_LINUX
else
CLANG_TIDY:=true
CLANG_TIDY_ARGS:=
endif

include kernel/Makefile
include $(ARCHDIR)/Makefile
include crypt/Makefile
include drivers/Makefile

ifeq ($(CONFIG_ACPI), y)
CPPFLAGS+=-Iinclude/acpica
include acpica/Makefile
endif

OBJS:=$(obj-y)

DEPS:=$(OBJS:%.o=%.d)

-include $(DEPS)

CRTI_OBJ:=lib/libk/$(ARCHDIR)/crti.o

CFLAGS_FOR_LINK:=$(CFLAGS)

ifneq ($(ONYX_USING_CLANG), yes)
# NOTE: We may not really want this
CRTBEGIN_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtbeginS.o)
CRTEND_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtendS.o)
LDFLAGS:=$(LDFLAGS) -no-pie
else
LDFLAGS:=$(LDFLAGS) -fno-sanitize-link-runtime -Wl,-no-pie
CFLAGS_FOR_LINK:=$(filter-out -mllvm -asan-instrumentation-with-call-threshold=0, $(CFLAGS_FOR_LINK))
endif

ifeq ($(ONYX_ARCH), arm64)
# ARM64 doesn't link with begin/endS
CRTBEGIN_OBJ:=
CRTEND_OBJ:=
endif

CRTN_OBJ:=lib/libk/$(ARCHDIR)/crtn.o

ifeq ($(ARCH_NO_CRTI_N), 1)
	CRTI_OBJ:=
	CRTN_OBJ:=
endif

ALL_OUR_OBJS:=\
$(CRTI_OBJ) \
$(OBJS) \
$(CRTN_OBJ) \

OBJ_DEPS:=$(CRTBEGIN_OBJ) \
$(OBJS) \
$(CRTEND_OBJ)

OBJ_LINK_LIST:=\
$(CRTI_OBJ) \
$(OBJ_DEPS) \
$(CRTN_OBJ) \

VDSO_LDFLAGS:= -Wl,-Bsymbolic -shared \
-Wl,-soname=onyx-vdso.so.0 -fpic \
-z max-page-size=0x1000 -z common-page-size=0x1000 \
-Wl,-T $(ARCHDIR)/vdso.ld

# Very important to note that right now, the vdso can only link on gcc using
# ld.bfd due to linker script weirdness. Because of that, we pass -fuse-ld=bfd if we're gcc
ifneq ($(ONYX_USING_CLANG), yes)
VDSO_LDFLAGS:=$(VDSO_LDFLAGS) -fuse-ld=bfd
endif

all: onyx-vdso.so.0 vmonyx

.PHONY: all clean install install-headers install-kernel kernel-modules

lib/libk/libk.a: $(libk-objs)
	$(AR) rcs $@ $(libk-objs)

vmonyx: $(OBJ_DEPS) $(EXTRA_LIBK_OBJS) $(ARCHDIR)/linker.ld $(kernel-archives) $(GENERATED_HEADERS)
	@echo [LD] $@
	$(CC) $(LDFLAGS) -Wl,-T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS_FOR_LINK) $(OBJ_LINK_LIST) $(LIBS) -Wno-error $(LIBK_LINK)
	cp vmonyx vmonyx-unstripped
	$(STRIP) -g vmonyx
ifeq ($(KERNEL_REQUIRES_FLATTENING), yes)
# For arm64 and others
	$(OBJCOPY) -O binary vmonyx vmonyx
endif

acpica/%.o: acpica/%.c $(GENERATED_HEADERS)
	@echo [CC] $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) $(CPPFLAGS)

kernel/mm/kasan.o: kernel/mm/kasan.cpp $(GENERATED_HEADERS)
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c++17 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) -fno-sanitize=address -fno-lto $(CPPFLAGS)

kernel/mm/malloc/%.o: kernel/mm/malloc/%.c $(GENERATED_HEADERS)
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c11 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) -fno-sanitize=address -fno-lto $(CPPFLAGS)

kernel/mm/malloc/%.o: kernel/mm/malloc/%.cpp $(GENERATED_HEADERS)
	@echo [CC] NOKASAN $<
	@$(CXX) -c $< -o $@ -std=c++20 $(ACPICA_CFLAGS) $(C_ONLY_CFLAGS) $(CXXFLAGS) -fno-sanitize=address -fno-lto $(CPPFLAGS)

kernel/ssp.o: kernel/ssp.cpp $(GENERATED_HEADERS)
	@echo [CC] NOKASAN $<
	@$(CC) -c $< -o $@ -std=c++2a $(CFLAGS) $(CXXFLAGS) -fno-stack-protector $(CPPFLAGS)

# I don't like this solution of having an ifeq RUN_CLANG_TIDY but I can't find a better way to do this and still pass $<

%.o: %.c $(GENERATED_HEADERS)
	@echo [CC] $<

#ifeq ($(RUN_CLANG_TIDY), 1)
#	$(CLANG_TIDY) $< $(CLANG_TIDY_ARGS)
#endif
	@$(CC) -c $< -o $@ -std=c11 $(CFLAGS) $(CPPFLAGS) $(C_ONLY_CFLAGS) -Wno-error=deprecated-declarations

%.o: %.S $(GENERATED_HEADERS)
	@echo [AS] $<
	@$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

%.o: %.cpp $(GENERATED_HEADERS)
	@echo [CXX] $<
	@$(CXX) -c $< -o $@ -std=c++20 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)

ifeq ($(RUN_CLANG_TIDY), 1)
	$(CLANG_TIDY) $< $(CLANG_TIDY_ARGS)
endif

$(ARCHDIR)/__vdso.o: $(ARCHDIR)/__vdso.c $(GENERATED_HEADERS)
	@echo [CC] $<
	$(CC) -O2 $(VDSO_CFLAGS) -c $< -o $@ -fpic -Iinclude -isystem lib/libk/include \
	-fno-stack-protector -fno-zero-initialized-in-bss

$(ARCHDIR)/__vdso_asm.o: $(ARCHDIR)/__vdso_asm.S $(GENERATED_HEADERS)
	@echo [AS] $<
	$(CC) -O2 -c $< -o $@ $(VDSO_CFLAGS) -fpic -Iinclude -isystem lib/libk/include \
	-fno-stack-protector -fno-zero-initialized-in-bss

onyx-vdso.so.0: $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o $(GENERATED_HEADERS)
	@echo [VDSO]
	$(CC) $(VDSO_LDFLAGS) $(ARCHDIR)/__vdso_asm.o $(ARCHDIR)/__vdso.o -o $@ -ffreestanding \
	 -nostdlib -Iinclude -Ilib/libk/include -Wl,--hash-style=both


$(info $(allkernelarchives))

clean: clean-modules
	rm -f vmonyx $(OBJS) $(DEPS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o
	rm -f clang-tidy.out
	rm -f kernel/syscall_thunk.cpp
	rm -rf include/onyx/gen
	rm -f $(kernel-archives)
	rm -f $(libk-objs)

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)


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
