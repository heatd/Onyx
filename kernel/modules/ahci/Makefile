MODULE:= ahci
MOD_OBJS:=$(wildcard *.c)
MODDIR:=/lib/modules
CFLAGS+=-Iinclude
all: $(MODULE)
	mkdir -p $(DESTDIR)$(MODDIR)/
	cp $(MODULE).kmod $(DESTDIR)$(MODDIR)/$(MODULE).kmod
$(MODULE): $(MOD_OBJS)
	echo [LD] $@.kmod
	$(CC) -c $(CFLAGS) $(LDFLAGS) $< -o $@.kmod
	echo $(CFLAGS)
clean:
	rm $(MODULE).kmod
