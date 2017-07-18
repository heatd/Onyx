PROG:= init
OBJS:= main.o daemon.o
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
	mkdir -p $(DESTDIR)/usr/share
	mkdir -p $(DESTDIR)/usr/share/man
	mkdir -p $(DESTDIR)/usr/share/man/man8
	cp $(PROG).8 $(DESTDIR)/usr/share/man/man8
	cp multi-user.target $(DESTDIR)/etc/init.d/targets
	rm -f $(DESTDIR)/etc/init.d/targets/default.target
	ln -s $(DESTDIR)/etc/init.d/targets/multi-user.target $(DESTDIR)/etc/init.d/targets/default.target
%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@ -ldrm
