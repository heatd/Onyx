# The static library uses .o objects
OBJS:=\
$(patsubst %.c,%.o,$(wildcard src/*.c)) \
# and the shared library uses .lo objects(built as PIC code)
OBJS_PIC:=\
$(patsubst %.c,%.lo,$(wildcard src/*.c))

LIBS:=libunwind.a \
libunwind.so
CFLAGS:=-Wall -Wextra -Werror -Wno-frame-address
CFLAGS_SHARED:=$(CFLAGS) -fPIC -DPIC
CPPFLAGS+=-Iinclude
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)
%.lo: %.c
	$(CC) -c $< -o $@ $(CFLAGS_SHARED) $(CPPFLAGS)
libunwind.a: $(OBJS)
	$(AR) rc $@ $(OBJS)
	mkdir -p lib
	mv $@ lib/
libunwind.so: $(OBJS_PIC)
	$(CC) $< -o $@ -shared
	mkdir -p lib
	mv $@ lib/
install-headers: include/
	cp -r include $(DESTDIR)/usr/
install: install-headers $(LIBS)
	cp -r lib $(DESTDIR)/usr/
clean:
	rm -f $(OBJS)
	rm -f $(OBJS_PIC)
	rm -rf lib
