kcsan-$(CONFIG_KCSAN)+= core.o report.o

obj-y+= $(patsubst %, kernel/kcsan/%, $(kcsan-y))

kernel/kcsan/%.o: CFLAGS+=-fno-sanitize=thread
