MODULES:=mod_example \
mod_dummyeth \
mod_ahci \
mod_bga \
mod_rtl8139

CFLAGS:=$(CFLAGS) -isystem $(realpath ../../libc/include) -I $(realpath ../../sysroot/usr/include) -mcmodel=kernel -D__is_onyx_kernel

all: $(MODULES)

mod_%: %
	make -C $</
clean:
	make -C example/ clean
