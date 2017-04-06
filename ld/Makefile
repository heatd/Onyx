PROG:= ld-onyx.so
OBJS:= start.o main.o
CFLAGS:=-O2 -g -std=c99 -fPIE
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	echo "Hello"
	mkdir -p $(DESTDIR)/lib
	cp $(PROG) $(DESTDIR)/lib
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -nostdlib -pie -l:libc_ld.a -Wl,-e,_dlstart -o $@
