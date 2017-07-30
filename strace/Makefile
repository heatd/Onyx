PROG:= strace
OBJS:= main.o
CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE -static
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@ -ldrm
