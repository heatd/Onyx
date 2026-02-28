linuxcompat-y:=lib/linuxcompat/completion.o \
			   lib/linuxcompat/srcu.o \
			   lib/linuxcompat/hexdump.o \
			   lib/linuxcompat/atomic.o \
			   lib/linuxcompat/rbtree.o \
			   lib/linuxcompat/idr.o \
			   lib/linuxcompat/xarray.o \
			   lib/linuxcompat/sched.o \
			   lib/linuxcompat/seq_buf.o \
			   lib/linuxcompat/radix-tree.o \
			   lib/linuxcompat/scatterlist.o

$(linuxcompat-y): CFLAGS+=-Wno-error=sign-compare
