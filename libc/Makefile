HOST?=$(shell ../default-host.sh)
HOSTARCH:=$(shell ../target-triplet-to-arch.sh $(HOST))

CFLAGS?=-O2 -g
CPPFLAGS?=
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
INCLUDEDIR?=$(PREFIX)/include
LIBDIR?=$(EXEC_PREFIX)/lib

CFLAGS:=$(CFLAGS) -Wall -Wextra -march=ivybridge
LIBK_CFLAGS:=$(CFLAGS) -ffreestanding -fbuiltin
LIBK_CPPFLAGS:=$(CPPFLAGS) -D__is_spartix_kernel

ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config

CFLAGS:=$(CFLAGS) $(ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(ARCH_CPPFLAGS)
LIBK_CFLAGS:=$(LIBK_CFLAGS) $(KERNEL_ARCH_CFLAGS)
LIBK_CPPFLAGS:=$(LIBK_CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS)

FREEOBJS:=\
$(ARCH_FREEOBJS) \
stdio/printf.o \
stdio/putchar.o \
stdio/puts.o \
stdlib/abort.o \
string/memcmp.o \
string/memcpy.o \
string/memmove.o \
string/memset.o \
string/strlen.o \
ssp/ssp.o \
string/strcpy.o \
string/strcmp.o \
string/strcat.o \
errno/errno.o \
ctype/to.o \
string/memchr.o \
string/strstr.o \
stdlib/qsort.o \
string/strtok.o \
math/fabs.o \
posix/posix_syscalls.o \
stdlib/malloc.o \


OBJS:=\
$(FREEOBJS) \
math/rand.o \
libc/init.o \

LIBK_OBJS:=$(FREEOBJS:.o=.libk.o) \

BINARIES=libc.a libg.a libk.a $(ARCHDIR)/crti.o $(ARCHDIR)/crtn.o $(ARCHDIR)/crt0.o

all: $(BINARIES)

.PHONY: all clean install install-headers install-libs

libc.a: $(OBJS)
	echo [AR] $(LIBC_OBJS)
	$(AR) rcs $@ $(OBJS)

libg.a:
	echo [AR] $(LIBG_OBJS)
	$(AR) rcs $@

libk.a: $(LIBK_OBJS)
	echo [AR] $(LIBK_OBJS)
	$(AR) rcs $@ $(LIBK_OBJS)

%.o: %.c
	echo [CC] $<
	$(CC) -c $< -o $@ -std=gnu11 $(CFLAGS) $(CPPFLAGS)
%.o: %.cpp
	echo [CXX] $<
	$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS)

%.libk.o: %.c
	echo [CC] $<.libk
	$(CC) -c $< -o $@ -std=gnu11 $(LIBK_CFLAGS) $(LIBK_CPPFLAGS)

%.libk.o: %.cpp
	echo [CXX] $<.libk
	$(CXX) -c $< -o $@ -std=c++14 $(LIBK_CFLAGS) $(LIBK_CPPFLAGS)

%.libk.o: %.S
	echo [AS] $<.libk
	nasm -felf$(NASMARCH) $< -o $@
%.o: %.S
	echo [AS] $<
	nasm -felf$(NASMARCH) $< -o $@
clean:
	rm -f $(BINARIES) $(OBJS) $(LIBK_OBJS) *.o */*.o */*/*.o

install: install-headers install-libs

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)

install-libs: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)
