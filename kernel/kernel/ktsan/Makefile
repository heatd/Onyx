ktsan-y:= access.o thread.o shadow.o clock.o sync.o init.o mutex.o events.o
ktsan-$(CONFIG_KUNIT)+= ktsan-tests.o

obj-$(CONFIG_KTSAN)+= $(patsubst %, kernel/ktsan/%, $(ktsan-y))

# None of this code can have TSAN enabled
kernel/ktsan/%.o: CFLAGS:=$(filter-out -fsanitize=thread -flto, $(CFLAGS))

kernel/ktsan/ktsan-tests.o: CFLAGS:=$(CFLAGS) -fsanitize=thread
