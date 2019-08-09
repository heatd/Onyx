PROG:= login
OBJS:= main.o

CFLAGS:=-O2 -g -fstack-protector-strong
CPPFLAGS:=-Wall -Wextra -Werror

clean:
	rm -f $(PROG)
	rm $(OBJS)
install: $(PROG)
	mkdir -p $(DESTDIR)/usr/bin/
	cp $(PROG) $(DESTDIR)/usr/bin/
$(PROG): $(OBJS)
	$(CXX) $(OBJS) $(CFLAGS) -o $@
