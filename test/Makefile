PROG:= test
OBJS:= src/tests.o \

CFLAGS:=-O2 -g -std=c99 -D_POSIX_C_SOURCE -static -ltest
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@
	strip $(PROG)
