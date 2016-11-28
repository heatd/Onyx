PROG:= init
OBJS:= main.o
CFLAGS:=-O2 -g
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/etc/init.d/
	echo "defaultrl:3" > $(DESTDIR)/etc/init.d/init.config
	echo "/bin/cat" > $(DESTDIR)/etc/init.d/rc3.d
	echo "PATH:=/bin:/usr/bin:/usr/local/bin:" > $(DESTDIR)/etc/init.d/rc3-envvar.d
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
%.o: %.S
	nasm -felf64 $< -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
