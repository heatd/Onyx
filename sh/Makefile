PROG:= sh
OBJS:= main.o login.o shell.o
CFLAGS:=-O2 -g -static -Iinclude
clean:
	rm -f $(PROG)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
