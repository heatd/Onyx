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
INCLUDEDIR?=$(PREFIX)/include

include ../kversion.config
CFLAGS:=$(CFLAGS) -mtune=pentium4 -ffreestanding -fbuiltin -Wall -Wextra -fstack-protector-strong
CPPFLAGS:=$(CPPFLAGS) -D__is_spartix_kernel -Iinclude -DKERNEL_VERSION='"$(KERNEL_VERSION)"' -DKERNEL_BRANCH='"$(KERNEL_BRANCH)"'
LDFLAGS:=$(LDFLAGS) -fwhole-program -fkeep-inline-functions -flto
LIBS:=$(LIBS) -nostdlib -lk -lgcc

ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config
CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS)
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS) $(BUILD_NUMBER_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)

DRIVERS:=drivers/ps2keyb \
	 drivers/serial \

include drivers/make.config

OBJS:=\
$(DRIVER_OBJS) \
$(KERNEL_ARCH_OBJS) \
kernel/kernel.o \
kernel/panic.o \
kernel/timer.o \
kernel/pmm.o \
kernel/kheap.o \
kernel/sleep.o \
kernel/fs.o \
kernel/initrd.o \
kernel/input_manager.o \
kernel/scheduler.o \
kernel/kthread.o \
kernel/fd.o \
kernel/sbrk.o \
kernel/fork.o \
kernel/fonts/font.o \
kernel/elf_loader.o \
kernel/spinlock.o \
kernel/process.o \
kernel/fs/devfs.o \
kernel/fs/null.o \
kernel/fs/zero.o \

CRTI_OBJ:=$(ARCHDIR)/crti.o
CRTBEGIN_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtbegin.o)
CRTEND_OBJ:=$(shell $(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=crtend.o)
CRTN_OBJ:=$(ARCHDIR)/crtn.o

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

all: vmspartix

.PHONY: all clean install install-headers install-kernel

vmspartix: BUILD $(OBJ_LINK_LIST) $(ARCHDIR)/linker.ld
	$(CC) -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

%.o: %.S
	nasm -felf32 $< -o $@

clean:
	rm -f vmspartix $(OBJS) $(ALL_OUR_OBJS) *.o */*.o */*/*.o

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)
	cp -RTv drivers/include $(DESTDIR)$(INCLUDEDIR)/drivers

install-kernel: vmspartix
	mkdir -p $(DESTDIR)$(BOOTDIR)
	cp vmspartix $(DESTDIR)$(BOOTDIR)
