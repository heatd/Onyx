PROGS:= pong
CFLAGS+=-static
CXXFLAGS+=-static -static-libstdc++
all: $(PROGS)

.PHONY: all install clean

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	install $(PROGS) $(DESTDIR)$(BINDIR)

%: %.c
	$(CC) -std=gnu11 $(CFLAGS) $(CPPFLAGS) $< -o $@ -ldrm

%: %.cpp
	$(CXX) -std=gnu++11 $(CXXFLAGS) $(CPPFLAGS) $< -o $@ -ldrm

clean:
	rm -f $(PROGS) *.o
