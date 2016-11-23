PROG:= echo
OBJS:= main.o
CFLAGS:=-O2 -g
clean:
	rm -f $(PROG)
install: $(PROG)
	mkdir -p $(DESTDIR)/bin/
	cp $(PROG) $(DESTDIR)/bin/
%.o: %.S
	nasm -felf64 $< -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $@
