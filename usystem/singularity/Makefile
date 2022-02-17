PROG:= singularity
OBJS:= main.o
CXXFLAGS+=-std=c++17
CPPFLAGS:=-Iinclude -D_POSIX_C_SOURCE

clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@

%.o: %.cpp
	$(CXX) -c $< $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) -o $@

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@ -lwserver
