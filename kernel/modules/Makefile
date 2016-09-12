MODULES:=mod_example
CFLAGS:=$(CFLAGS) -mcmodel=large
all: $(MODULES)

mod_%: %
	make -C $</
clean:
	make -C example/ clean
