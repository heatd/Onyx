PROG:= dhcpcd
OBJS:= dhcpcd.o
CFLAGS:=-Og -g -std=c99 -D_POSIX_C_SOURCE -fstack-protector-strong -no-pie
CPPFLAGS:=-Iinclude

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

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -Iinclude -o $@
