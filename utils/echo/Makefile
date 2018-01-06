PROG:= echo
OBJS:= main.o
CFLAGS:=-O2 -g -static -fstack-protector-strong
clean:
	rm -f $(PROG)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
