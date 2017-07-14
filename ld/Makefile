PROG:= ld-onyx.so
OBJS:= start.o main.o utils.o
CFLAGS:=-O2 -g -std=c99 -fPIE -Iinclude
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/lib
	cp $(PROG) $(DESTDIR)/usr/lib
	echo "Installing $(PROG)"
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -nostdlib -pie -l:libc_ld.a -Wl,-e,_dlstart -o $@
