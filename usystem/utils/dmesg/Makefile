PROG:= dmesg
OBJS:= main.o
CFLAGS:=-O2 -g -fstack-protector-strong
clean:
	rm -f $(PROG)
	rm main.o
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
