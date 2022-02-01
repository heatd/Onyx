PROG:= strace
OBJS:= main.o syscalls.o
CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE -D_GNU_SOURCE
clean:
	rm -f $(PROG)
	rm -f $(OBJS)

ifeq ($(ONYX_ARCH), x86_64)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
else
# Don't build strace on non x86_64 as it's not supported
# This is no big deal since this strace is pretty broken and not terribly useful

install:

endif

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
