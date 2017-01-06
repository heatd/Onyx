MODULES:=mod_example \
mod_dummyeth \
mod_drm
CFLAGS:=$(CFLAGS) -mcmodel=large
all: $(MODULES)

mod_%: %
	make -C $</
clean:
	make -C example/ clean
