PROG:= wserver
OBJS:= main.o display.o window.o server.o
CFLAGS:=-O2 -g -std=c99 -static -march=sandybridge -fstack-protector-strong
CPPFLAGS:=-Iinclude -D_POSIX_C_SOURCE

clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/etc/
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/etc/init.d/targets
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
	cp graphical.target $(DESTDIR)/etc/init.d/targets/
%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@ -ldrm
