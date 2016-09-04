PROG:= cat
OBJS:= asm.o main.o
CFLAGS:=-ffreestanding -O2 -g
clean:
	rm -f $(PROG)
install: $(PROG)
	mkdir -p $(DESTDIR)/bin/
	cp $(PROG) $(DESTDIR)/bin/
%.o: %.S
	nasm -felf64 $< -o $@
$(PROG): $(OBJS)
	$(CC) -nostartfiles -Wl,-emain $(OBJS) -o $@
