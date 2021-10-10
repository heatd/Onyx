PROG:= strace
OBJS:= main.o syscalls.o
CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE -D_GNU_SOURCE
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
