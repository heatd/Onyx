LIBS:=libphoton.so libphoton.a
CXXFLAGS:=-O2 -g -std=c++20 -fstack-protector-strong -fPIC -DPIC -D_GNU_SOURCE
CPPFLAGS:=-Iinclude -D_POSIX_C_SOURCE

ifeq ($(ONYX_ARCH), riscv64)
CXXFLAGS+=-mno-relax
endif

BINARIES:= $(LIBS)

include src/Makefile

libphoton.so: $(libphoton_objs)
	$(CXX) -shared $< -o $@

libphoton.a: $(libphoton_objs)
	$(AR) rcs $@ $(libphoton_objs)

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	mkdir -p $(DESTDIR)$(INCLUDEDIR)/photon
	cp -RTv include $(DESTDIR)$(INCLUDEDIR)/photon

install: $(BINARIES)
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp $(BINARIES) $(DESTDIR)$(LIBDIR)

clean:
	rm -f $(libphoton_objs) $(BINARIES)
