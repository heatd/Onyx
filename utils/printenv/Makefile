PROG:= printenv
OBJS:= main.o
CFLAGS:=-O2 -g -fstack-protector-strong
clean:
	rm -f $(PROG)
	rm $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
