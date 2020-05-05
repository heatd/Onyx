fs-y:= block.o dentry.o dev.o file.o mtable.o null.o pagecache.o partition.o pipe.o poll.o pseudo.o \
	superblock.o sysfs.o tmpfs.o vfs.o zero.o buffer.o

include kernel/fs/ext2/Makefile

obj-y+= $(patsubst %, kernel/fs/%, $(fs-y))
