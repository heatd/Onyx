HOST?=$(shell ../default-host.sh)
HOSTARCH:=$(shell ../target-triplet-to-arch.sh $(HOST))

CFLAGS?=-O2 -g
CPPFLAGS?=-Iinclude
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -Wall -Wextra -mtune=generic -fPIC -DPIC

CFLAGS:=$(CFLAGS)
CPPFLAGS:=$(CPPFLAGS)

OBJS:=\
$(patsubst %.c,%.o,$(wildcard src/*.c))

BINARIES=libdrm.a libdrm.so

all: $(BINARIES)

.PHONY: all clean install install-headers install-libs

%.o: %.c
	echo [CC] $<
	$(CC) -c $< -o $@ -std=gnu11 $(CFLAGS) $(CPPFLAGS)
%.o: %.cpp
	echo [CXX] $<
	$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS)

%.libk.o: %.S
	echo [AS] $<.libk
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
%.o: %.S
	echo [AS] $<
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
clean:
	rm -f $(BINARIES) $(OBJS) $(LIBK_OBJS) *.o */*.o */*/*.o

libdrm.a: $(OBJS)
	echo [AR] $(LIBC_OBJS)
	$(AR) rcs $@ $(OBJS)

libdrm.so: $(OBJS)
	$(CC) -shared $(OBJS) -o $@

install: install-headers install-libs
install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)

install-libs: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)
