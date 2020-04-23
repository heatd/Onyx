PROG:= testsuite
OBJS:= src/futex_test.o \
       src/mmap_test.o

CXXFLAGS:=-O2 -g -std=c++17 -D_POSIX_C_SOURCE -ltest

clean:
	rm -f $(PROG)
	rm -f $(OBJS)

install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $@
