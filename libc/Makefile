HOST?=$(shell ../default-host.sh)
HOSTARCH:=$(shell ../target-triplet-to-arch.sh $(HOST))

CFLAGS?=-O2 -g
CPPFLAGS?=-D__is_onyx_libc
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -mtune=generic -Wno-error
LIBK_CFLAGS:=$(CFLAGS) -ffreestanding -fbuiltin
LIBK_CPPFLAGS:=$(CPPFLAGS) -D__is_onyx_kernel

ARCHDIR:=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config

CFLAGS:=$(CFLAGS) $(ARCH_CFLAGS) -fPIC
CPPFLAGS:=$(CPPFLAGS) $(ARCH_CPPFLAGS) -DPIC
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
stdlib/malloc.o \
string/wmemcpy.o \
string/memccpy.o \
string/strerror.o \
string/stpcpy.o \
string/strdup.o \
stdlib/_Exit.o \
stdio/fprintf.o \
stdio/fread.o \
stdio/fwrite.o \
stdio/sprintf.o \
stdio/stdio.o \
stdio/stdstream.o \
stdio/perror.o \
stdlib/rand.o \
libc/__tls_get_addr.o \
stdio/ftell.o \
stdio/fopen.o \
stdio/fseek.o \
stdio/rewind.o \
stdio/fgets.o \
stdio/gets.o \
stdio/fclose.o \
stdio/tmpnam.o \
string/strcspn.o \
string/strspn.o \
string/strchrnul.o \
misc/basename.o \
misc/dirname.o \
posix/sigaddset.o \
posix/sigandset.o \
posix/sigdelset.o \
posix/sigemptyset.o \
posix/sigfillset.o \
posix/sigisemptyset.o \
posix/sigismember.o \
posix/sigorset.o
OBJS:=\
$(FREEOBJS) \
libc/init.o \
posix/memory.o \
posix/io.o \
posix/signal.o \
posix/time.o \
posix/process.o \
posix/uio.o
LIBK_OBJS:=$(FREEOBJS:.o=.libk.o) \

LD_SPARTIX_OBJS:=ld/main.o

BINARIES=libc.a libg.a libk.a $(ARCHDIR)/crti.o $(ARCHDIR)/crtn.o $(ARCHDIR)/crt0.o $(ARCHDIR)/Scrt0.o

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
libc.so: $(OBJS)
	$(CC) $(OBJS) -shared $(CFLAGS) $(CPPFLAGS) -o $@
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $@ $(DESTDIR)$(LIBDIR)
ld-onyx.so: $(LD_SPARTIX_OBJS)
	#$(CC) $(LD_SPARTIX_OBJS) -Wl,-Bstatic -shared -lc $(CFLAGS) $(CPPFLAGS) -o $@
	mkdir -p $(DESTDIR)/usr/lib
%.o: %.c
	echo [CC] $<
	$(CC) -c $< -o $@ -std=gnu11 -fPIC $(CFLAGS) $(CPPFLAGS)
%.o: %.cpp
	echo [CXX] $<
	$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS)

%.libk.o: %.c
	echo [CC] $<.libk
	$(CC) -c $< -o $@ -std=gnu11 -mcmodel=kernel $(LIBK_CFLAGS) $(LIBK_CPPFLAGS)

%.libk.o: %.cpp
	echo [CXX] $<.libk
	$(CXX) -c $< -o $@ -std=c++14 -mcmode=kernel $(LIBK_CFLAGS) $(LIBK_CPPFLAGS)

%.libk.o: %.S
	echo [AS] $<.libk
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
%.o: %.S
	echo [AS] $<
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
clean:
	rm -f $(BINARIES) $(OBJS) $(LIBK_OBJS) *.o */*.o */*/*.o

install: install-headers install-libs ld-onyx.so

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)

install-libs: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)
