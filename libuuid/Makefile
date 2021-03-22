CFLAGS?=-O2 -g
CPPFLAGS?=-Iinclude
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -Wall -Wextra -fPIC -DPIC

CFLAGS:=$(CFLAGS)
CPPFLAGS:=$(CPPFLAGS)

OBJS:=\
$(patsubst %.cpp,%.o,$(wildcard src/*.cpp))

BINARIES=libuuid.a libuuid.so

all: $(BINARIES)

.PHONY: all clean install install-headers install-libs

%.o: %.c
	echo [CC] $<
	$(CC) -c $< -o $@ -std=gnu11 $(CFLAGS) $(CPPFLAGS)
%.o: %.cpp
	echo [CXX] $<
	$(CXX) -c $< -o $@ -std=c++14 $(CFLAGS) $(CPPFLAGS)

%.o: %.S
	echo [AS] $<
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
clean:
	rm -f $(BINARIES) $(OBJS) $(LIBK_OBJS) *.o */*.o */*/*.o

libuuid.a: $(OBJS)
	echo [AR] $(LIBC_OBJS)
	$(AR) rcs $@ $(OBJS)

libuuid.so: $(OBJS)
	$(CC) -shared $(OBJS) -o $@

install: install-headers install-libs
install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	mkdir -p $(DESTDIR)$(INCLUDEDIR)/uuid
	cp -RTv uuid.h $(DESTDIR)$(INCLUDEDIR)/uuid/uuid.h

install-libs: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)
