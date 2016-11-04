PROG:= init
OBJS:= main.o
CFLAGS:=-O2 -g
clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
%.o: %.S
	nasm -felf64 $< -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
