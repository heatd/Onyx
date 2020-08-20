PROG:= ping
OBJS:= ping.o
CFLAGS:=-O2 -g -fstack-protector-strong
clean:
	rm -f $(PROG) $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@
