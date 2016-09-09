PROG:= init
OBJS:= main.o
CFLAGS:=-O2 -g -static -nostartfiles
clean:
	rm -f $(PROG)
install: $(PROG)
	mkdir -p $(DESTDIR)/sbin/
	cp $(PROG) $(DESTDIR)/sbin/
%.o: %.S
	nasm -felf64 $< -o $@
$(PROG): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -lg -lm -lnosys -o $@
