PROG:= wserver
LIB:=libwserver.so
OBJS:= main.o display.o buffer.o server.o window.o client.o
CFLAGS:=-O2 -g -std=c++17 -march=sandybridge -fstack-protector-strong -lpthread
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
	$(CXX) -c $< $(CFLAGS) $(CPPFLAGS) -o $@

$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@ -ldrm

libwserver/lib.o: libwserver/lib.c 
	$(CC) -c $< -march=sandybridge -fstack-protector-strong -std=c11 $(CPPFLAGS) -o $@ -fPIC -DPIC

$(LIB): $(PROG) libwserver/lib.o
	$(CC) -shared libwserver/lib.o -ldrm -o $@