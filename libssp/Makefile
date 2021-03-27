CFLAGS?=-O2 -g
CPPFLAGS?=-Iinclude
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
INCLUDEDIR?=$(PREFIX)/usr/include
LIBDIR?=$(EXEC_PREFIX)/usr/lib

CFLAGS:=$(CFLAGS) -Wall -Wextra -mtune=generic -fno-stack-protector

CFLAGS:=$(CFLAGS)
CPPFLAGS:=$(CPPFLAGS)

OBJS:=\
$(patsubst %.c,%.o,$(wildcard *.c))

BINARIES=libssp_nonshared.a libssp.a

all: $(BINARIES)

.PHONY: all clean install install-headers install-libs

%.o: %.c
	$(CC) -c $< -o $@ -std=gnu11 $(CFLAGS) $(CPPFLAGS)

clean:
	rm -f $(BINARIES) $(OBJS) $(LIBK_OBJS) *.o */*.o */*/*.o

libssp_nonshared.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)
libssp.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

install: install-libs

install-libs: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)
