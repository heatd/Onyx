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
CFLAGS:=$(CFLAGS) -ffreestanding -mcmodel=kernel -mno-red-zone -fbuiltin -Wall -Wextra -fstack-protector-strong -ftree-vectorize -ftree-vectorizer-verbose=7 -mno-aes -mno-mmx -mno-pclmul -mno-sse -mno-sse2 -mno-sse3 -mno-sse4 -mno-sse4a -mno-fma4 -mno-ssse3
CPPFLAGS:=$(CPPFLAGS) -D__is_spartix_kernel -Iinclude -DKERNEL_VERSION='"$(KERNEL_VERSION)"' -DKERNEL_BRANCH='"$(KERNEL_BRANCH)"' -DKERNEL_ARCH='"$(KERNEL_ARCH)"'
LDFLAGS:=$(LDFLAGS) -z max-page-size=0x1000 -fwhole-program -fkeep-inline-functions -flto
LIBS:=$(LIBS) -nostdlib -lk -lgcc
CXXFLAGS:=-fno-exceptions -fno-rtti
ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config
CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS)
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS) $(BUILD_NUMBER_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)

OBJS:=\
$(patsubst %.cpp,%.o,$(wildcard drivers/softwarefb/*.cpp)) \
$(patsubst %.cpp,%.o,$(wildcard kernel/*.cpp)) \
$(patsubst %.cpp,%.o,$(wildcard kernel/*/*.cpp)) \
$(patsubst %.cpp,%.o,$(wildcard $(ARCHDIR)/*.cpp)) \
$(filter-out $(ARCHDIR)/crti.o, $(patsubst %.S,%.o,$(wildcard $(ARCHDIR)/*.S)))
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
	echo $(OBJS)
	$(CC) -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(OBJ_LINK_LIST) $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

%.o: %.S
	nasm -felf64 $< -o $@

%.o: %.cpp
	$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS)

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
