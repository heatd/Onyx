PROG:= packmanager
C_FILES:= main.c
# We need different CFLAGS for the different builds - simply because most Linux distros don't have the static libc packages
# To avoid more dependencies, we just build the host version dynamically linked - Onyx's build is statically linked.
HOST_CFLAGS:=-O2 -g
CFLAGS:=-O2 -g -static
clean:
	rm -f $(PROG)
install: $(PROG) $(PROG)-host
	mkdir -p $(DESTDIR)/bin/
	cp $(PROG) $(DESTDIR)/bin/
$(PROG)-host: $(C_FILES)
	$(HOST_CC) $(C_FILES) $(HOST_CFLAGS) -o $@
$(PROG): $(C_FILES)
	$(CC) $(C_FILES) $(CFLAGS) -o $@
