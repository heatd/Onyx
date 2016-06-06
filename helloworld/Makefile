clean:
	rm -f helloworld
install: helloworld
	cp helloworld $(DESTDIR)/boot/
helloworld:
	$(CC) -O2 -g -ffreestanding -nostdlib -lk -lgcc -Wl,-emain -o $@ main.c
