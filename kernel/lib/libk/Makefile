LIBK_OBJS:=\
stdio/printf.o \
stdio/puts.o \
string/memcmp.o \
string/memset_explicit.o \
string/strlen.o \
string/strcpy.o \
string/strcmp.o \
string/strcat.o \
ctype/to.o \
string/memchr.o \
stdlib/qsort.o \
string/strtok.o \
math/fabs.o \
string/wmemcpy.o \
string/memccpy.o \
string/strerror.o \
string/stpcpy.o \
string/strdup.o \
stdio/sprintf.o \
stdio/perror.o \
stdlib/rand.o \
libc/__tls_get_addr.o \
stdio/ftell.o \
stdio/fopen.o \
stdio/fseek.o \
stdio/rewind.o \
stdio/fgets.o \
stdio/gets.o \
stdio/fclose.o \
stdio/tmpnam.o \
string/strcspn.o \
string/strspn.o \
string/strchrnul.o \
misc/basename.o \
misc/dirname.o \
posix/sigaddset.o \
posix/sigandset.o \
posix/sigdelset.o \
posix/sigemptyset.o \
posix/sigfillset.o \
posix/sigisemptyset.o \
posix/sigismember.o \
posix/sigorset.o \
string/strchr.o \
string/strtoul.o \
$(LIBK_ARCH_OBJS)

libk-objs:=$(patsubst %, lib/libk/%, $(LIBK_OBJS))

kernel-archives:=$(kernel-archives) lib/libk/libk.a

EXTRA_LIBK_OBJS:=$(patsubst %, lib/libk/%, $(LIBK_EXTRA_OBJ))
