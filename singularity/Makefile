PROG:= singularity
OBJS:= main.o
CFLAGS:=-O2 -g -std=c++17 -march=sandybridge -fstack-protector-strong
CPPFLAGS:=-Iinclude -D_POSIX_C_SOURCE

clean:
	rm -f $(PROG)
	rm -f $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
	cp graphical.target $(DESTDIR)/etc/init.d/targets/
%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@
%.o: %.cpp
	$(CXX) -c $< $(CFLAGS) $(CPPFLAGS) -o $@
$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@
