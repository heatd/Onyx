PROG:= init
OBJS:= main.o
CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/etc/init.d/
	echo "defaultrl:3" > $(DESTDIR)/etc/init.d/init.config
	echo "/bin/login" > $(DESTDIR)/etc/init.d/rc3.d
	echo "PATH:=/bin:/usr/bin:/usr/local/bin:" > $(DESTDIR)/etc/init.d/rc3-envvar.d
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
	mkdir -p $(DESTDIR)/usr/share
	mkdir -p $(DESTDIR)/usr/share/man
	mkdir -p $(DESTDIR)/usr/share/man/man8
	cp $(PROG).8 $(DESTDIR)/usr/share/man/man8
%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@ -ldrm
