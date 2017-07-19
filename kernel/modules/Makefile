MODULES:=mod_example \
mod_dummyeth \
mod_drm \
mod_ahci \
mod_svga \
mod_bga \
mod_rtl8139

CFLAGS:=$(CFLAGS) -mcmodel=large
all: $(MODULES)

mod_%: %
	make -C $</
clean:
	make -C example/ clean
