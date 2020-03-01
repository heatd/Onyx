PROG:= devmgrd
OBJS:= src/main.o
CFLAGS:=-O2 -g -D_POSIX_C_SOURCE -fstack-protector-strong
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/etc
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/etc/init.d/targets
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
	cp devmgr.service $(DESTDIR)/etc/init.d/targets
%.o: %.c
	$(CC) -c $< $(CFLAGS) -Iinclude -o $@
%.o: %.cpp
	$(CXX) -c $< $(CFLAGS) -Iinclude -o $@

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -Iinclude -o $@
