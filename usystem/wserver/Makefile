PROG:= wserver
LIB:=libwserver.so
OBJS:= main.o display.o buffer.o server.o window.o client.o
CXXFLAGS+=-std=c++17
CPPFLAGS:=-Iinclude -D_POSIX_C_SOURCE

clean:
	rm -f $(PROG)
	rm -f $(LIB)
	rm -f $(OBJS)
	rm -f libwserver/lib.o

install: $(PROG) $(LIB)
	mkdir -p $(DESTDIR)/etc/
	mkdir -p $(DESTDIR)/etc/init.d/
	mkdir -p $(DESTDIR)/etc/init.d/targets
	mkdir -p $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/usr/lib
	mkdir -p $(DESTDIR)/usr/include
	cp $(PROG) $(DESTDIR)/usr/bin/
	cp $(LIB) $(DESTDIR)/usr/lib
	cp include/wserver_public_api.h $(DESTDIR)/usr/include
	cp graphical.target $(DESTDIR)/etc/init.d/targets/

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@

%.o: %.cpp
	$(CXX) -c $< $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) -o $@

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@ -lphoton

libwserver/lib.o: libwserver/lib.c 
	$(CC) -c $< $(CFLAGS) $(CPPFLAGS) -o $@ -fPIC -DPIC

$(LIB): $(PROG) libwserver/lib.o
	$(CC) $(CFLAGS) -shared libwserver/lib.o -lphoton -o $@
