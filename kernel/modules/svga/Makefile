MODULE:= svga
MOD_OBJS:=$(wildcard *.c)
MODDIR:=/usr/lib/modules
all: $(MODULE)
	mkdir -p $(DESTDIR)$(MODDIR)/
	cp $(MODULE).kmod $(DESTDIR)$(MODDIR)/$(MODULE).kmod
$(MODULE): $(MOD_OBJS)
	echo [LD] $@.kmod
	$(CC) -c $(CFLAGS) $(LDFLAGS) -Iinclude $< -o $@.kmod
clean:
	rm $(MODULE).kmod
