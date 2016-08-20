clean:
	rm -f helloworld
install: helloworld
	cp helloworld $(DESTDIR)/boot/
helloworld:
	nasm -felf64 asm.S -o asm.o
	$(CC) -O2 -g -ffreestanding -c -o main.o main.c
	$(CC) -nostartfiles -Wl,-emain main.o asm.o -o $@
