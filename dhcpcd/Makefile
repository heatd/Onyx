PROG:= dhcpcd
OBJS:= dhcpcd.o
CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE -static
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/etc/init.d/targets
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
	cp dhcpcd.service $(DESTDIR)/etc/init.d/targets
%.o: %.c
	$(CC) -c $< $(CFLAGS) -Iinclude -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -Iinclude -o $@
