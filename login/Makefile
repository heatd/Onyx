PROG:= login
OBJS:= main.o
CFLAGS:=-O2 -g -static
clean:
	rm -f $(PROG)
	rm $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/bin/
	cp $(PROG) $(DESTDIR)/bin/
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
